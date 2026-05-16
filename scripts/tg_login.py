"""One-time Telegram MTProto login — produces the TG_SESSION string.

The attacker user account must authorize once; after that the saved
StringSession is reused with no further codes.

Two steps (run from the repo root, with TG_API_ID / TG_API_HASH in the env):

  1. Request the login code (Telegram sends it to that account's app):

       uv run python scripts/tg_login.py request +15551234567

  2. Sign in with the code you received (and 2FA password if the account
     has one):

       uv run python scripts/tg_login.py signin 12345
       uv run python scripts/tg_login.py signin 12345 my2FApassword

Step 2 prints the StringSession — put it in `.env` as TG_SESSION.
Intermediate state is held in `.tg_login_state.json` (gitignored) between
the two steps.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

STATE_FILE = Path(".tg_login_state.json")


def _creds() -> tuple[int, str]:
    api_id = os.environ.get("TG_API_ID", "").strip()
    api_hash = os.environ.get("TG_API_HASH", "").strip()
    if not (api_id and api_hash):
        sys.exit("TG_API_ID / TG_API_HASH not set. `set -a; . ./.env; set +a` first.")
    return int(api_id), api_hash


def _request(phone: str) -> int:
    from telethon.sessions import StringSession
    from telethon.sync import TelegramClient

    api_id, api_hash = _creds()
    client = TelegramClient(StringSession(), api_id, api_hash)
    client.connect()
    try:
        sent = client.send_code_request(phone)
        STATE_FILE.write_text(json.dumps({
            "phone": phone,
            "phone_code_hash": sent.phone_code_hash,
            "session": client.session.save(),
        }))
        # Holds a live Telethon session credential — keep it owner-only.
        STATE_FILE.chmod(0o600)
    finally:
        client.disconnect()
    print(f"Login code sent to {phone} (check the Telegram app's 'Telegram' "
          f"service chat).\nNext:  uv run python scripts/tg_login.py signin <code>")
    return 0


def _signin(code: str, password: str | None) -> int:
    from telethon.errors import SessionPasswordNeededError
    from telethon.sessions import StringSession
    from telethon.sync import TelegramClient

    if not STATE_FILE.exists():
        sys.exit("no .tg_login_state.json — run the `request` step first.")
    state = json.loads(STATE_FILE.read_text())
    api_id, api_hash = _creds()
    client = TelegramClient(StringSession(state["session"]), api_id, api_hash)
    client.connect()
    try:
        try:
            client.sign_in(phone=state["phone"], code=code,
                            phone_code_hash=state["phone_code_hash"])
        except SessionPasswordNeededError:
            if not password:
                sys.exit("account has 2FA — re-run: signin <code> <2fa_password>")
            client.sign_in(password=password)
        me = client.get_me()
        session_str = client.session.save()
    finally:
        client.disconnect()
    STATE_FILE.unlink(missing_ok=True)
    print(f"\nLogged in as @{getattr(me, 'username', None) or me.first_name} "
          f"(id={me.id}).\n\nTG_SESSION:\n{session_str}\n")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "request":
        return _request(argv[1])
    if len(argv) >= 2 and argv[0] == "signin":
        return _signin(argv[1], argv[2] if len(argv) > 2 else None)
    sys.exit(__doc__)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
