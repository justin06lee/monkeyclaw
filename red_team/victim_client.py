"""Transport-agnostic chat client for talking to a NemoClaw victim.

Three schemes are supported:

- `mock://chat/<id>` — in-process lookup against `red_team.mock_victim`'s
  registry. Used for tests and Phase B development.
- `http://...` / `https://...` — POST `{"message": "..."}` to the endpoint
  with a 30s timeout. Expects `{"reply": "..."}` back.
- `ipc:///path/to.sock` — Unix-domain socket. Each turn is one line of
  JSON in each direction. This is what the real NemoClaw CLI exposes per
  Person 1's provisioning.

The client never crashes the lane on transport errors — it raises
`VictimError`, which the execution agent catches and treats as a turn
where the victim refused / disconnected.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.parse

import httpx

from red_team import mock_victim
from red_team.mock_victim import TurnSideEffects

LOG = logging.getLogger("monkeyclaw.red.victim_client")


class VictimError(RuntimeError):
    """Transport-layer failure talking to a victim."""


class VictimClient:
    """Send turns to a victim via whatever transport `chat_endpoint` implies."""

    def __init__(self, chat_endpoint: str, timeout_s: float = 30.0) -> None:
        self.chat_endpoint = chat_endpoint
        self.timeout_s = timeout_s
        self.scheme = urllib.parse.urlparse(chat_endpoint).scheme or ""
        self._http: httpx.Client | None = None

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None

    def __enter__(self) -> "VictimClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def send(self, message: str) -> tuple[str, TurnSideEffects | None]:
        """Send a message; return (reply, side_effects).

        side_effects is non-None only for the `mock://` transport — real
        HTTP/IPC victims surface their side-effects through the monitoring
        harness's filesystem and network captures.
        """
        if self.scheme == "mock":
            return self._send_mock(message)
        if self.scheme in ("http", "https"):
            return self._send_http(message), None
        if self.scheme == "ipc":
            return self._send_ipc(message), None
        raise VictimError(f"unsupported chat_endpoint scheme: {self.chat_endpoint!r}")

    # ------------------------------------------------------------------
    def _send_mock(self, message: str) -> tuple[str, TurnSideEffects]:
        victim = mock_victim.lookup(self.chat_endpoint)
        if victim is None:
            raise VictimError(
                f"no mock victim registered for {self.chat_endpoint!r}. "
                f"Register one via red_team.mock_victim.register() before sending."
            )
        return victim.chat(message)

    def _send_http(self, message: str) -> str:
        if self._http is None:
            self._http = httpx.Client(timeout=self.timeout_s)
        try:
            r = self._http.post(
                self.chat_endpoint,
                json={"message": message},
            )
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise VictimError(f"http chat failed: {e}") from e
        # Be liberal in what we accept.
        for k in ("reply", "response", "content", "message", "text"):
            v = data.get(k)
            if isinstance(v, str):
                return v
        raise VictimError(f"http response missing reply field: {data}")

    def _send_ipc(self, message: str) -> str:
        # parse ipc:///path → /path
        path = self.chat_endpoint[len("ipc://"):]
        if not os.path.exists(path):
            raise VictimError(f"ipc socket missing: {path}")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout_s)
                s.connect(path)
                s.sendall((json.dumps({"message": message}) + "\n").encode("utf-8"))
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise VictimError(f"ipc chat failed: {e}") from e
        try:
            data = json.loads(buf.decode("utf-8").strip() or "{}")
        except json.JSONDecodeError as e:
            raise VictimError(f"ipc response not JSON: {e}") from e
        for k in ("reply", "response", "content", "message", "text"):
            v = data.get(k)
            if isinstance(v, str):
                return v
        raise VictimError(f"ipc response missing reply field: {data}")


def estimate_tokens(s: str) -> int:
    """Cheap character-based token estimate. Good enough for accounting."""
    return max(1, len(s) // 4)


__all__ = ["VictimClient", "VictimError", "estimate_tokens"]
