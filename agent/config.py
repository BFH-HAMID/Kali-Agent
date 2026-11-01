"""Persistent configuration for KaliAgent.

There is deliberately **no** ``.env`` file.  The Gemini API key lives in
``~/.config/kali-agent/config.json`` with ``chmod 600`` and is requested with a
hidden prompt (``getpass``) the first time the agent runs.

Environment variable ``KALI_AGENT_HOME`` can relocate the config directory
(used by the unit tests so they never touch the real home directory).
"""

from __future__ import annotations

import getpass
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

APP_NAME = "kali-agent"
DEFAULT_MODEL = "gemini-2.5-pro"

#: ``~/.config/kali-agent`` unless overridden.
CONFIG_DIR: Path = Path(
    os.environ.get("KALI_AGENT_HOME", str(Path.home() / ".config" / APP_NAME))
)
CONFIG_FILE: Path = CONFIG_DIR / "config.json"
CATALOG_FILE: Path = CONFIG_DIR / "tools_catalog.json"

_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600
_DIR_MODE = stat.S_IRWXU  # 0o700


@dataclass
class Config:
    """Everything KaliAgent needs to persist between runs."""

    api_key: str = ""
    model: str = DEFAULT_MODEL
    scope: list[str] = field(default_factory=list)
    max_steps: int = 40
    created_at: str = ""

    # ------------------------------------------------------------------ io
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}
        cfg = cls(**clean)
        if isinstance(cfg.scope, str):  # be forgiving with hand-edited files
            cfg.scope = [s for s in cfg.scope.replace(",", " ").split() if s]
        return cfg


# --------------------------------------------------------------------- paths
def ensure_config_dir() -> Path:
    """Create the config directory with restrictive permissions."""

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, _DIR_MODE)
    except OSError:  # pragma: no cover - unusual filesystems
        pass
    return CONFIG_DIR


def load_config() -> Config | None:
    """Load the config file, returning ``None`` when it does not exist yet."""

    if not CONFIG_FILE.exists():
        return None
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[kali-agent] could not read {CONFIG_FILE}: {exc}", file=sys.stderr)
        return None
    if not isinstance(raw, dict):
        return None
    return Config.from_dict(raw)


def save_config(config: Config) -> Path:
    """Atomically write the config file and lock it down to the owner only."""

    ensure_config_dir()
    if not config.created_at:
        config.created_at = datetime.now(UTC).isoformat(timespec="seconds")
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config.to_dict(), indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, _FILE_MODE)
    tmp.replace(CONFIG_FILE)
    try:
        os.chmod(CONFIG_FILE, _FILE_MODE)
    except OSError:  # pragma: no cover
        pass
    return CONFIG_FILE


# ---------------------------------------------------------------- api key io
def mask_key(key: str) -> str:
    """Return a display-safe version of an API key."""

    if not key:
        return "<none>"
    if len(key) <= 10:
        return key[:2] + "*" * max(len(key) - 2, 0)
    return f"{key[:6]}...{key[-4:]}"


def prompt_for_api_key() -> str:
    """Ask for the Gemini API key with a hidden prompt."""

    print(
        "\n  KaliAgent needs a Gemini API key (https://aistudio.google.com/apikey).\n"
        "  It is stored in "
        f"{CONFIG_FILE} with chmod 600 and is never sent anywhere except Google's API.\n"
    )
    while True:
        key = getpass.getpass("  Gemini API key: ").strip()
        if key:
            if len(key) < 20:
                print("  That looks too short - try again (Ctrl+C to abort).\n")
                continue
            return key
        print("  An empty key is not useful. Try again, or press Ctrl+C.\n")


def ensure_config(
    *,
    model: str | None = None,
    scope: list[str] | None = None,
    interactive: bool = True,
) -> Config:
    """Load the config, creating it (and asking for a key) on first run."""

    config = load_config()
    changed = False

    if config is None:
        config = Config()
        changed = True

    if not config.api_key:
        env_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if env_key:
            config.api_key = env_key
            changed = True
        elif interactive:
            config.api_key = prompt_for_api_key()
            changed = True
        else:
            raise RuntimeError(
                "No Gemini API key configured. Run without --non-interactive to set one."
            )

    if model and model != config.model:
        config.model = model
        changed = True
    if scope is not None and scope != config.scope:
        config.scope = scope
        changed = True

    if changed or not CONFIG_FILE.exists():
        save_config(config)
    return config


def reset_api_key() -> None:
    """Forget the stored key (keeps model/scope preferences)."""

    config = load_config() or Config()
    config.api_key = ""
    save_config(config)
    if CONFIG_FILE.exists():
        print(f"[kali-agent] API key cleared from {CONFIG_FILE}")


def config_summary(config: Config) -> str:
    """Single-line human readable summary used by the status bar."""

    scope = ", ".join(config.scope) if config.scope else "unrestricted"
    return (
        f"model={config.model} | key={mask_key(config.api_key)} | "
        f"scope={scope} | config={CONFIG_FILE}"
    )
