"""Telegram MTProto victim transport.

Lets MonkeyClaw red-team a NemoClaw agent **through its Telegram channel** —
the agent listens on its own bot, and a bot cannot DM another bot, so the
attacker must be a real Telegram *user account* driven over MTProto.

This module wraps a Telethon user-account client as a turn-based victim
transport: `send(text)` DMs the victim's bot and blocks until the agent
replies, mirroring `VictimClient`'s `(reply, side_effects)` contract.

Credentials (all from the environment, kept out of git):
- ``TG_API_ID`` / ``TG_API_HASH`` — from my.telegram.org
- ``TG_SESSION``                  — StringSession from `scripts/tg_login.py`

The attack target is the bot handle encoded in a ``tg://<bot_username>``
endpoint. Side-effects are always ``None``: a Telegram attack is judged from
the transcript by the Tier-2 semantic judge (prompt-injection / social-eng),
not from filesystem/network capture.
"""

from __future__ import annotations

import logging
import os
import time

LOG = logging.getLogger("monkeyclaw.telegram")


class TelegramVictimError(RuntimeError):
    """Raised on a Telegram transport failure (login, send, or no reply)."""


def _creds() -> tuple[int, str, str]:
    api_id = os.environ.get("TG_API_ID", "").strip()
    api_hash = os.environ.get("TG_API_HASH", "").strip()
    session = os.environ.get("TG_SESSION", "").strip()
    if not (api_id and api_hash):
        raise TelegramVictimError(
            "TG_API_ID / TG_API_HASH not set — get them from my.telegram.org."
        )
    if not session:
        raise TelegramVictimError(
            "TG_SESSION not set — run `uv run python scripts/tg_login.py` first."
        )
    try:
        return int(api_id), api_hash, session
    except ValueError as e:
        raise TelegramVictimError(f"TG_API_ID must be numeric, got {api_id!r}") from e


class TelegramVictimSession:
    """One authenticated MTProto session attacking a single victim bot.

    Reused across `send()` calls so a multi-turn attack is one continuous
    Telegram conversation with the agent.
    """

    def __init__(self, bot_username: str, *, response_timeout_s: float = 600.0,
                 poll_interval_s: float = 3.0) -> None:
        # Accept "tg://bot", "@bot", or "bot".
        handle = bot_username.split("://", 1)[-1].strip().lstrip("@")
        if not handle:
            raise TelegramVictimError("empty victim bot username")
        self.bot_username = handle
        self.response_timeout_s = response_timeout_s
        self.poll_interval_s = poll_interval_s
        self._client = None  # telethon.sync.TelegramClient
        self._entity = None
        self._last_seen_id = 0

    # ------------------------------------------------------------------
    def connect(self) -> None:
        try:
            from telethon.sessions import StringSession
            from telethon.sync import TelegramClient
        except ImportError as e:  # pragma: no cover - hard dep
            raise TelegramVictimError(
                "telethon not installed — run `uv add telethon`."
            ) from e

        api_id, api_hash, session = _creds()
        client = TelegramClient(StringSession(session), api_id, api_hash)
        client.connect()
        if not client.is_user_authorized():
            client.disconnect()
            raise TelegramVictimError(
                "TG_SESSION is not authorized — re-run scripts/tg_login.py."
            )
        self._client = client
        try:
            self._entity = client.get_entity(self.bot_username)
        except Exception as e:  # noqa: BLE001
            self.close()
            raise TelegramVictimError(
                f"could not resolve victim bot @{self.bot_username}: {e}"
            ) from e
        # Baseline: ignore any history already in the chat. Only messages that
        # arrive *after* this point count as the agent's replies.
        try:
            recent = client.get_messages(self._entity, limit=1)
            me = client.get_me()
        except Exception as e:  # noqa: BLE001 - any Telethon error is transport
            self.close()
            raise TelegramVictimError(
                f"failed to baseline Telegram session: {e}"
            ) from e
        self._last_seen_id = recent[0].id if recent else 0
        LOG.info("telegram attacker @%s connected; target=@%s",
                 getattr(me, "username", "?"), self.bot_username)

    # ------------------------------------------------------------------
    def send(self, text: str) -> tuple[str, None]:
        """DM the victim bot and block until the agent replies.

        Returns ``(reply_text, None)`` — None side-effects per the
        `VictimClient` contract for non-mock transports.
        """
        if self._client is None or self._entity is None:
            raise TelegramVictimError("not connected — call connect() first.")
        try:
            sent = self._client.send_message(self._entity, text)
        except Exception as e:  # noqa: BLE001 - any Telethon error is transport
            raise TelegramVictimError(
                f"failed to send message to @{self.bot_username}: {e}"
            ) from e
        LOG.debug("telegram> sent msg %s to @%s", sent.id, self.bot_username)

        deadline = time.time() + self.response_timeout_s
        while time.time() < deadline:
            time.sleep(self.poll_interval_s)
            replies = self._drain_replies()
            if replies:
                self._last_seen_id = max(m.id for m in replies)
                # The agent may answer in several bubbles — join them.
                return "\n".join(m.message for m in replies), None
        raise TelegramVictimError(
            f"victim bot @{self.bot_username} did not reply within "
            f"{self.response_timeout_s:.0f}s"
        )

    # ------------------------------------------------------------------
    # Per-poll page size. The agent can answer in many bubbles; one
    # `get_messages` page may not cover them all, so `_drain_replies` keeps
    # paging until no message newer than `_last_seen_id` remains.
    _PAGE_SIZE = 50

    def _drain_replies(self) -> list:
        """Collect every incoming message newer than `_last_seen_id`.

        Pages through history so a burst of >page-size agent bubbles in a
        single poll interval is not silently truncated. Returned oldest-first.
        """
        assert self._client is not None and self._entity is not None
        collected: list = []
        max_id = 0  # 0 == no upper bound (newest page)
        while True:
            try:
                # `max_id` excludes ids >= max_id, so each loop walks older.
                page = self._client.get_messages(
                    self._entity, limit=self._PAGE_SIZE,
                    min_id=self._last_seen_id,
                    max_id=max_id)
            except Exception as e:  # noqa: BLE001 - any Telethon error is transport
                raise TelegramVictimError(
                    f"failed to fetch replies from @{self.bot_username}: {e}"
                ) from e
            fresh = [m for m in page
                     if not m.out and m.id > self._last_seen_id and m.message]
            collected.extend(fresh)
            if len(page) < self._PAGE_SIZE:
                break  # last page reached
            max_id = min(m.id for m in page)
        collected.sort(key=lambda m: m.id)
        return collected

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self._client = None
        self._entity = None

    def __enter__(self) -> TelegramVictimSession:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


__all__ = ["TelegramVictimError", "TelegramVictimSession"]
