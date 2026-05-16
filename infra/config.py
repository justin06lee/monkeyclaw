"""YAML config loader + logging setup.

Loading model:
1. start with all defaults from `MonkeyClawConfig`
2. layer `configs/monkeyclaw.yaml` if it exists
3. layer the path passed via `--config` or `MC_CONFIG` env var

Environment variables override individual fields with the prefix `MC_`, e.g.
`MC_LANES__POOL_SIZE=8` overrides `lanes.pool_size`. Double-underscore = nesting.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Any

import yaml

from interfaces.config_schema import MonkeyClawConfig

LOG = logging.getLogger("monkeyclaw.config")

DEFAULT_PATH = Path("configs/monkeyclaw.yaml")
ENV_PREFIX = "MC_"


def _deep_merge(base: dict, layer: dict) -> dict:
    out = dict(base)
    for k, v in layer.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env_overrides(prefix: str = ENV_PREFIX) -> dict[str, Any]:
    """Translate MC_FOO__BAR=42 into {"foo": {"bar": "42"}}."""
    out: dict[str, Any] = {}
    for k, v in os.environ.items():
        if not k.startswith(prefix):
            continue
        path = k[len(prefix):].lower().split("__")
        cursor: dict[str, Any] = out
        for p in path[:-1]:
            cursor = cursor.setdefault(p, {})
        cursor[path[-1]] = _coerce(v)
    return out


def _coerce(v: str) -> Any:
    """Light scalar coercion for env vars.

    Only obvious booleans are coerced here. Numeric-looking strings are left
    as strings on purpose: force-coercing them would corrupt string-typed
    config fields (e.g. a zero-padded ID like "007"). Pydantic performs the
    correct per-field type coercion/validation when the model is constructed.
    """
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    return v


def load_config(path: str | Path | None = None) -> MonkeyClawConfig:
    """Load layered config: defaults → file → env."""
    merged: dict[str, Any] = {}
    # (path, is_explicit): an auto-discovered DEFAULT_PATH is optional, but an
    # explicitly-requested config (--config / MC_CONFIG) that is missing is a
    # hard error — silently ignoring it would run with the wrong settings.
    candidates: list[tuple[Path, bool]] = []
    if DEFAULT_PATH.exists():
        candidates.append((DEFAULT_PATH, False))
    if path is not None:
        candidates.append((Path(path), True))
    env_path = os.environ.get("MC_CONFIG")
    if env_path:
        candidates.append((Path(env_path), True))
    for p, explicit in candidates:
        if not p.exists():
            if explicit:
                raise FileNotFoundError(
                    f"explicitly-requested config file not found: {p}")
            LOG.warning("config %s not found, skipping", p)
            continue
        with p.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        merged = _deep_merge(merged, data)
    merged = _deep_merge(merged, _env_overrides())
    cfg = MonkeyClawConfig(**merged)
    # Convenience env vars for the two most-overridden secrets — simpler than
    # the nested MC_NOTIFICATIONS__TELEGRAM_BOT_TOKEN form.
    tok = os.environ.get("MC_TELEGRAM_BOT_TOKEN")
    if tok:
        cfg.notifications.telegram_bot_token = tok
    chat = os.environ.get("MC_TELEGRAM_CHAT_ID")
    if chat:
        cfg.notifications.telegram_chat_id = chat
    return cfg


def setup_logging(cfg: MonkeyClawConfig) -> None:
    """Configure root logger with stream + rotating file handler."""
    level = getattr(logging, cfg.logging.level.upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(level)
    # Wipe any existing handlers so re-config in tests is clean.
    for h in list(root.handlers):
        root.removeHandler(h)
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root.addHandler(stream)
    if cfg.logging.file:
        path = Path(cfg.logging.file)
        path.parent.mkdir(parents=True, exist_ok=True)
        rh = logging.handlers.RotatingFileHandler(
            path.as_posix(),
            maxBytes=cfg.logging.rotate_max_bytes,
            backupCount=cfg.logging.rotate_backups,
        )
        rh.setFormatter(fmt)
        root.addHandler(rh)
