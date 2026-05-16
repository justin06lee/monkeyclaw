"""Transport-agnostic chat client for talking to a NemoClaw victim.

Shared infrastructure — Contract 4 allows this module as a cross-boundary
import alongside `red_team/checks.py`. red_team's execution agent and
blue_team's replay/cold-verify paths both speak to victim instances via
this client; centralizing it here avoids any cross-team coupling.

Four transports are supported:

- `mock://chat/<id>` — in-process lookup against the registry below. Used
  by tests and Phase B development. The registered object must expose a
  `chat(message: str) -> tuple[str, TurnSideEffects]` method
  (see `MockVictimProtocol`); the planted-vulnerability `MockVictim`
  implementation lives in `red_team/mock_victim.py`.
- `ws://...` / `wss://...` — the real OpenClaw Control gateway. Speaks the
  gateway's JSON-over-WebSocket protocol: an Ed25519 device-signed
  `connect` handshake, then `chat.send` requests whose replies stream back
  as `agent` / `chat` events. This is the transport used against a live
  NemoClaw sandbox. See `_GatewayConnection` for the wire protocol.
- `http://...` / `https://...` — POST `{"message": "..."}` to the endpoint
  with a 30s timeout. Expects `{"reply": "..."}` back.
- `ipc:///path/to.sock` — Unix-domain socket. Each turn is one line of
  JSON in each direction.

The client never crashes the lane on transport errors — it raises
`VictimError`, which the execution agent catches and treats as a turn
where the victim refused / disconnected.

This module has NO imports from `red_team/` or `blue_team/`. It depends
only on stdlib + httpx + `interfaces/types.py`, plus `websockets` and
`cryptography` (lazily imported, only when a `ws://` endpoint is used).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import socket
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from interfaces.types import InferenceEvent, NetworkEvent

LOG = logging.getLogger("monkeyclaw.victim_client")


# ---------------------------------------------------------------------------
# Side-effects shape — produced by mock victims, consumed by execution agents
# ---------------------------------------------------------------------------


@dataclass
class TurnSideEffects:
    """Side-effects produced by a single victim turn.

    Real (HTTP / IPC / WebSocket) victims don't return this — their
    side-effects flow through the monitoring harness via filesystem
    snapshots and network captures. The mock transport returns this
    directly so the execution agent can forward `network_events` and
    `inference_events` to the harness without an out-of-band channel.
    """

    fs_files_written: list[str] = field(default_factory=list)
    network_events: list[NetworkEvent] = field(default_factory=list)
    inference_events: list[InferenceEvent] = field(default_factory=list)
    revealed_secret: bool = False


@runtime_checkable
class MockVictimProtocol(Protocol):
    """Anything registered with the mock registry must look like this.

    The concrete planted-vulnerability implementation
    (`red_team.mock_victim.MockVictim`) satisfies this protocol; tests
    and other red-team fixtures can register their own.
    """

    def chat(self, message: str) -> tuple[str, TurnSideEffects]:
        ...


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class VictimError(RuntimeError):
    """Transport-layer failure talking to a victim."""


class GatewayError(VictimError):
    """Gateway-level failure — failed handshake or a rejected gateway request.

    A subclass of VictimError so existing callers that catch VictimError
    treat a gateway failure as a refused/disconnected turn.
    """


# ---------------------------------------------------------------------------
# Mock victim registry — generic mechanism, keyed by chat_endpoint
# ---------------------------------------------------------------------------


_REGISTRY: dict[str, MockVictimProtocol] = {}
_REGISTRY_LOCK = threading.Lock()


def register(endpoint: str, victim: MockVictimProtocol) -> None:
    with _REGISTRY_LOCK:
        _REGISTRY[endpoint] = victim


def unregister(endpoint: str) -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.pop(endpoint, None)


def lookup(endpoint: str) -> MockVictimProtocol | None:
    with _REGISTRY_LOCK:
        return _REGISTRY.get(endpoint)


def reset_all() -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


# ---------------------------------------------------------------------------
# OpenClaw Control gateway — JSON-over-WebSocket protocol
# ---------------------------------------------------------------------------
#
# Discovered against a live NemoClaw sandbox (gateway v2026.4.24, protocol 3).
# The dashboard SPA speaks this same protocol; the constants below are the
# values its `connect` request uses.
#
#   1. open WS, send Origin header matching the gateway page
#   2. server -> {"type":"event","event":"connect.challenge",
#                 "payload":{"nonce":...,"ts":...}}
#   3. client -> {"type":"req","id":...,"method":"connect","params":{...}}
#      where params.device carries an Ed25519 signature over the canonical
#      string  v2|deviceId|clientId|clientMode|role|scopes|signedAtMs|token|nonce
#   4. server -> {"type":"res","id":...,"ok":true,"payload":{"type":"hello-ok"}}
#   5. chat:  {"type":"req",...,"method":"chat.send",
#              "params":{"sessionKey":...,"message":...,"deliver":false,
#                        "idempotencyKey":...}}
#      reply streams back as event frames; the turn is complete on a
#      `chat` event with state=="final".

_GW_CLIENT_ID = "openclaw-control-ui"
_GW_CLIENT_VERSION = "control-ui"
_GW_CLIENT_MODE = "webchat"
_GW_ROLE = "operator"
_GW_SCOPES = [
    "operator.admin", "operator.read", "operator.write",
    "operator.approvals", "operator.pairing",
]
_GW_CAPS = ["tool-events"]
_GW_PROTOCOL = 3
_GW_DEFAULT_SESSION = "agent:main:main"


def _b64url(raw: bytes) -> str:
    """Base64url-encode without padding (matches the dashboard's `nn()`)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass
class _DeviceIdentity:
    """Ephemeral Ed25519 device identity for the gateway handshake.

    The gateway authorizes a fresh device when the connect request carries
    a valid gateway token in the signed payload, so we generate a new
    keypair per connection rather than persisting one.
    """

    device_id: str          # hex(SHA-256(public_key_bytes))
    public_b64: str         # base64url(public_key_bytes)
    _signer: Any            # Ed25519PrivateKey

    @classmethod
    def generate(cls) -> _DeviceIdentity:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        sk = Ed25519PrivateKey.generate()
        public = sk.public_key().public_bytes_raw()
        return cls(
            device_id=hashlib.sha256(public).hexdigest(),
            public_b64=_b64url(public),
            _signer=sk,
        )

    def sign(self, message: str) -> str:
        return _b64url(self._signer.sign(message.encode("utf-8")))


def _gateway_token_env() -> str | None:
    """Fallback token source for standalone use (provisioner passes it
    explicitly otherwise)."""
    tok = os.environ.get("MC_GATEWAY_TOKEN", "").strip()
    return tok or None


class _GatewayConnection:
    """One authenticated WebSocket session to the OpenClaw Control gateway.

    Reused across `send_message` calls so a multi-turn attack runs against
    a single connection (and a single agent session).
    """

    def __init__(
        self,
        endpoint: str,
        auth_token: str,
        origin: str,
        *,
        open_timeout: float,
        response_timeout: float,
        session_key: str = _GW_DEFAULT_SESSION,
    ) -> None:
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.origin = origin
        self.open_timeout = open_timeout
        self.response_timeout = response_timeout
        self.session_key = session_key
        self._ws: Any = None  # websockets.sync.client.ClientConnection

    # ------------------------------------------------------------------
    def connect(self) -> None:
        from websockets.sync.client import connect as ws_connect

        try:
            self._ws = ws_connect(
                self.endpoint,
                additional_headers={"Origin": self.origin},
                open_timeout=self.open_timeout,
                max_size=16 * 1024 * 1024,
            )
        except Exception as e:  # noqa: BLE001
            raise GatewayError(f"gateway WebSocket connect failed: {e}") from e

        try:
            challenge = self._recv(self.open_timeout)
        except Exception as e:  # noqa: BLE001
            self.close()
            raise GatewayError(f"no connect.challenge from gateway: {e}") from e

        nonce = None
        if (challenge.get("type") == "event"
                and challenge.get("event") == "connect.challenge"):
            nonce = (challenge.get("payload") or {}).get("nonce")
        if not nonce:
            self.close()
            raise GatewayError(f"unexpected first frame from gateway: {challenge}")

        hello = self._request("connect", self._connect_params(nonce),
                               timeout=self.open_timeout)
        if hello.get("type") != "res" or not hello.get("ok"):
            self.close()
            raise GatewayError(f"gateway connect rejected: {hello.get('error') or hello}")
        LOG.debug("gateway connected: %s", hello.get("payload", {}).get("server"))

        # Resolve a concrete session to chat against. Best-effort: fall back
        # to the well-known main session if discovery fails.
        try:
            self.session_key = self._discover_session() or self.session_key
        except Exception as e:  # noqa: BLE001
            LOG.debug("session discovery failed, using %s: %s", self.session_key, e)

    def _connect_params(self, nonce: str) -> dict[str, Any]:
        device = _DeviceIdentity.generate()
        signed_at = int(time.time() * 1000)
        canonical = "|".join([
            "v2", device.device_id, _GW_CLIENT_ID, _GW_CLIENT_MODE, _GW_ROLE,
            ",".join(_GW_SCOPES), str(signed_at), self.auth_token, nonce,
        ])
        return {
            "minProtocol": _GW_PROTOCOL,
            "maxProtocol": _GW_PROTOCOL,
            "client": {
                "id": _GW_CLIENT_ID,
                "version": _GW_CLIENT_VERSION,
                "platform": "web",
                "mode": _GW_CLIENT_MODE,
            },
            "role": _GW_ROLE,
            "scopes": list(_GW_SCOPES),
            "device": {
                "id": device.device_id,
                "publicKey": device.public_b64,
                "signature": device.sign(canonical),
                "signedAt": signed_at,
                "nonce": nonce,
            },
            "caps": list(_GW_CAPS),
            "auth": {"token": self.auth_token},
            "userAgent": "monkeyclaw-victim-client/1.0",
            "locale": "en-US",
        }

    def _discover_session(self) -> str | None:
        res = self._request("sessions.list", {}, timeout=self.open_timeout)
        if res.get("type") == "res" and res.get("ok"):
            sessions = (res.get("payload") or {}).get("sessions") or []
            if sessions:
                return sessions[0].get("key")
        return None

    # ------------------------------------------------------------------
    # Back-to-back `chat.send`s no-op while the agent is still working the
    # previous run: the gateway answers with a degenerate `chat`/final that
    # has no `message` and no preceding `agent` lifecycle. We detect that
    # and resend after a backoff. The patience is generous on purpose — the
    # victim may run a large model on CPU, so a single turn can take tens of
    # seconds; lanes run sequentially so the wall-time cost is acceptable.
    _SEND_ATTEMPTS = 6
    _SEND_BACKOFF_S = (5.0, 12.0, 25.0, 40.0, 60.0)

    def send_message(self, text: str) -> str:
        """Send one turn via `chat.send`; return the agent's final reply text.

        Retries if the gateway no-ops the message because the agent is still
        busy settling the previous run.
        """
        if self._ws is None:
            raise GatewayError("gateway connection not established")
        for attempt in range(self._SEND_ATTEMPTS):
            # The gateway echoes idempotencyKey back as runId, so we know the
            # run_id up front and filter this turn's events strictly —
            # trailing events from a prior turn may still be in flight on the
            # shared connection.
            run_id = str(uuid.uuid4())
            req_id = str(uuid.uuid4())
            self._send({
                "type": "req",
                "id": req_id,
                "method": "chat.send",
                "params": {
                    "sessionKey": self.session_key,
                    "message": text,
                    "deliver": False,
                    "idempotencyKey": run_id,
                },
            })
            reply, agent_ran = self._collect_reply(req_id, run_id)
            if agent_ran:
                return reply
            if attempt + 1 < self._SEND_ATTEMPTS:
                backoff = self._SEND_BACKOFF_S[
                    min(attempt, len(self._SEND_BACKOFF_S) - 1)
                ]
                LOG.debug("gateway no-op'd chat.send (agent busy); "
                          "retry %d after %.0fs", attempt + 2, backoff)
                time.sleep(backoff)
        raise GatewayError(
            f"gateway no-op'd chat.send {self._SEND_ATTEMPTS} times "
            "(agent never picked up the message)"
        )

    # Grace period to wait for the authoritative `chat`/final frame after
    # the agent run's lifecycle `phase:end` event (they arrive a few ms apart).
    _RUN_END_GRACE_S = 8.0

    def _collect_reply(self, req_id: str, run_id: str) -> tuple[str, bool]:
        """Read frames until run `run_id` produces a final message.

        Returns `(reply_text, agent_ran)`. `agent_ran` is False when the
        gateway no-op'd the send (degenerate `chat`/final with no `message`
        and no `agent` lifecycle) — the caller resends in that case.

        The authoritative reply is the `chat` event with state=="final".
        The agent's `lifecycle`/`phase:end` event arrives slightly *before*
        it, so we don't complete on `phase:end` — we only use it to start a
        short grace window guarding against a missing final frame.
        """
        deadline = time.monotonic() + self.response_timeout
        grace_deadline: float | None = None
        streamed: list[str] = []
        agent_ran = False

        while True:
            now = time.monotonic()
            remaining = deadline - now
            if grace_deadline is not None:
                remaining = min(remaining, grace_deadline - now)
            if remaining <= 0:
                if grace_deadline is not None:
                    # Run ended but no final `chat` frame — return what we
                    # streamed (may be empty if the agent stayed silent).
                    return "".join(streamed), agent_ran
                raise GatewayError("timed out waiting for gateway chat reply")

            frame = self._recv(remaining)
            ftype = frame.get("type")

            if ftype == "res" and frame.get("id") == req_id:
                if not frame.get("ok"):
                    raise GatewayError(
                        f"chat.send rejected: {frame.get('error') or frame}"
                    )
                continue

            if ftype != "event":
                continue
            payload = frame.get("payload") or {}
            # Strictly this turn's run only — drop other runs and runless
            # housekeeping events (health, tick).
            if payload.get("runId") != run_id:
                continue

            event = frame.get("event")
            if event == "agent" and payload.get("stream") == "assistant":
                agent_ran = True
                delta = (payload.get("data") or {}).get("delta")
                if isinstance(delta, str):
                    streamed.append(delta)
            elif event == "chat" and payload.get("state") == "final":
                text = _extract_text(payload.get("message"))
                if "message" in payload or text:
                    agent_ran = True
                return (text or "".join(streamed)), agent_ran
            elif event == "agent" and payload.get("stream") == "lifecycle":
                phase = (payload.get("data") or {}).get("phase")
                if phase == "start":
                    agent_ran = True
                elif phase == "end":
                    grace_deadline = time.monotonic() + self._RUN_END_GRACE_S

    # ------------------------------------------------------------------
    def _request(self, method: str, params: dict[str, Any],
                  *, timeout: float) -> dict[str, Any]:
        req_id = str(uuid.uuid4())
        self._send({"type": "req", "id": req_id, "method": method,
                    "params": params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GatewayError(f"timed out waiting for `{method}` response")
            frame = self._recv(remaining)
            if frame.get("type") == "res" and frame.get("id") == req_id:
                return frame
            # otherwise: an interleaved event — keep reading.

    def _send(self, obj: dict[str, Any]) -> None:
        try:
            self._ws.send(json.dumps(obj))
        except Exception as e:  # noqa: BLE001
            raise GatewayError(f"gateway send failed: {e}") from e

    def _recv(self, timeout: float) -> dict[str, Any]:
        try:
            raw = self._ws.recv(timeout=timeout)
        except TimeoutError as e:
            raise GatewayError("gateway recv timed out") from e
        except Exception as e:  # noqa: BLE001
            raise GatewayError(f"gateway recv failed: {e}") from e
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except (ValueError, TypeError) as e:
            raise GatewayError(f"gateway sent non-JSON frame: {raw[:200]!r}") from e

    def close(self) -> None:
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:  # noqa: BLE001
                pass
            self._ws = None


def _extract_text(message: Any) -> str:
    """Join the text parts of a gateway `chat` message payload."""
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = [
        part["text"]
        for part in content
        if isinstance(part, dict) and part.get("type") == "text"
        and isinstance(part.get("text"), str)
    ]
    return "".join(parts)


# ---------------------------------------------------------------------------
# Transport client
# ---------------------------------------------------------------------------


class VictimClient:
    """Send turns to a victim via whatever transport `chat_endpoint` implies.

    For `ws://` / `wss://` endpoints the gateway needs an auth token. Pass
    it as `auth_token=`, or set `MC_GATEWAY_TOKEN` in the environment. The
    `origin` defaults to `http://<host>` of the endpoint, which the gateway
    requires to match an allowed Control-UI origin.
    """

    def __init__(
        self,
        chat_endpoint: str,
        timeout_s: float = 30.0,
        *,
        auth_token: str | None = None,
        origin: str | None = None,
        response_timeout_s: float = 600.0,
    ) -> None:
        self.chat_endpoint = chat_endpoint
        self.timeout_s = timeout_s
        self.response_timeout_s = response_timeout_s
        self.scheme = urllib.parse.urlparse(chat_endpoint).scheme or ""
        self.auth_token = auth_token
        self.origin = origin
        self._http: httpx.Client | None = None
        self._gateway: _GatewayConnection | None = None
        self._tg: Any = None  # interfaces.telegram_victim.TelegramVictimSession

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None
        if self._gateway is not None:
            self._gateway.close()
            self._gateway = None
        if self._tg is not None:
            self._tg.close()
            self._tg = None

    def __enter__(self) -> VictimClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def send(self, message: str) -> tuple[str, TurnSideEffects | None]:
        """Send a message; return (reply, side_effects).

        side_effects is non-None only for the `mock://` transport — real
        HTTP/IPC/WebSocket victims surface their side-effects through the
        monitoring harness's filesystem and network captures.
        """
        if self.scheme == "mock":
            return self._send_mock(message)
        if self.scheme in ("ws", "wss"):
            return self._send_ws(message), None
        if self.scheme in ("http", "https"):
            return self._send_http(message), None
        if self.scheme == "ipc":
            return self._send_ipc(message), None
        if self.scheme == "tg":
            return self._send_tg(message)
        raise VictimError(f"unsupported chat_endpoint scheme: {self.chat_endpoint!r}")

    # ------------------------------------------------------------------
    def _send_tg(self, message: str) -> tuple[str, TurnSideEffects | None]:
        """Attack a victim agent over its Telegram channel (`tg://<bot>`).

        The MTProto session is lazily created and reused across turns so a
        multi-turn attack is one continuous Telegram conversation.
        """
        if self._tg is None:
            from interfaces.telegram_victim import (
                TelegramVictimError,
                TelegramVictimSession,
            )
            try:
                self._tg = TelegramVictimSession(
                    self.chat_endpoint, response_timeout_s=self.response_timeout_s)
                self._tg.connect()
            except TelegramVictimError as e:
                raise VictimError(str(e)) from e
        try:
            return self._tg.send(message)
        except Exception as e:  # noqa: BLE001
            raise VictimError(f"telegram transport error: {e}") from e

    # ------------------------------------------------------------------
    def _send_mock(self, message: str) -> tuple[str, TurnSideEffects]:
        victim = lookup(self.chat_endpoint)
        if victim is None:
            raise VictimError(
                f"no mock victim registered for {self.chat_endpoint!r}. "
                f"Register one via interfaces.victim_client.register() before sending."
            )
        return victim.chat(message)

    # ------------------------------------------------------------------
    def _send_ws(self, message: str) -> str:
        if self._gateway is None:
            token = self.auth_token or _gateway_token_env()
            if not token:
                raise GatewayError(
                    "gateway endpoint needs an auth token: pass auth_token= to "
                    "VictimClient or set MC_GATEWAY_TOKEN in the environment."
                )
            parsed = urllib.parse.urlparse(self.chat_endpoint)
            origin = self.origin or f"http://{parsed.netloc}"
            gateway = _GatewayConnection(
                self.chat_endpoint, token, origin,
                open_timeout=self.timeout_s,
                response_timeout=self.response_timeout_s,
            )
            gateway.connect()
            self._gateway = gateway
        return self._gateway.send_message(message)

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
        for k in ("reply", "response", "content", "message", "text"):
            v = data.get(k)
            if isinstance(v, str):
                return v
        raise VictimError(f"http response missing reply field: {data}")

    def _send_ipc(self, message: str) -> str:
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


__all__ = [
    "GatewayError",
    "MockVictimProtocol",
    "TurnSideEffects",
    "VictimClient",
    "VictimError",
    "estimate_tokens",
    "lookup",
    "register",
    "reset_all",
    "unregister",
]
