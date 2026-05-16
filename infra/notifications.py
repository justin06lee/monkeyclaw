"""Notification dispatch — Telegram + generic webhook.

Used as the `alert_sink` plugged into `MCPServer.send_alert`. Falls back to a
no-op if no telegram/webhook config is supplied — the alert is still persisted
to the `alerts` table.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

import httpx

from interfaces.config_schema import NotificationsConfig

LOG = logging.getLogger("monkeyclaw.notify")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_at_least(actual: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(actual.lower(), 0) >= SEVERITY_ORDER.get(floor.lower(), 0)


class AlertDispatcher:
    """Multiplexes alert delivery across telegram + webhooks.

    Construct once during bootstrap; pass `.send` to `MCPServer(alert_sink=...)`.
    """

    def __init__(self, cfg: NotificationsConfig) -> None:
        self.cfg = cfg
        self._client = httpx.Client(timeout=httpx.Timeout(10.0))

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AlertDispatcher:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _scrub(self, text: str) -> str:
        """Redact the Telegram bot token from any string before logging."""
        tok = self.cfg.telegram_bot_token
        return text.replace(tok, "***") if tok else text

    # ------------------------------------------------------------------
    def send(self, message: str, severity: str) -> None:
        if not severity_at_least(severity, self.cfg.alert_severity_floor):
            LOG.debug("alert below floor (%s < %s) — dropping", severity, self.cfg.alert_severity_floor)
            return
        prefixed = f"[{severity.upper()}] {message}"
        ok_count = 0
        if self.cfg.telegram_bot_token and self.cfg.telegram_chat_id:
            try:
                self._send_telegram(prefixed)
                ok_count += 1
            except Exception as e:  # noqa: BLE001
                # The bot token is embedded in the Telegram request URL, so it
                # appears inside any httpx exception. Scrub it before logging.
                LOG.warning("telegram delivery failed: %s",
                            self._scrub(str(e)))
        for url in self.cfg.webhook_urls:
            try:
                self._send_webhook(url, message, severity)
                ok_count += 1
            except Exception as e:  # noqa: BLE001
                LOG.warning("webhook %s failed: %s", url, e)
        if ok_count == 0:
            # Stay quiet on stderr if nothing is wired — caller knows.
            LOG.debug("no notification channels configured")

    # ------------------------------------------------------------------
    def _send_telegram(self, text: str) -> None:
        # Plain text — no parse_mode. The alerts carry literal markers like
        # "[INFO]"/"[CRITICAL]" which Markdown would mis-parse as links and
        # strip the brackets from.
        url = f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage"
        resp = self._client.post(url, json={
            "chat_id": self.cfg.telegram_chat_id,
            "text": text,
        })
        resp.raise_for_status()

    def _send_webhook(self, url: str, message: str, severity: str) -> None:
        resp = self._client.post(url, content=json.dumps({
            "service": "monkeyclaw",
            "message": message,
            "severity": severity,
        }), headers={"Content-Type": "application/json"})
        resp.raise_for_status()


def stdout_sink() -> Callable[[str, str], None]:
    def _sink(message: str, severity: str) -> None:
        print(f"[ALERT {severity.upper()}] {message}", flush=True)
    return _sink
