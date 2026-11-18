"""
env_utils.py
------------
Environment variable management for the steganography CLI.

Responsibilities:
  - Load .env from project root (auto-discovered relative to this file).
  - Auto-generate cryptographically secure STEGO_SECRET_KEY and ADMIN_KEY
    if they are absent from .env.
  - Provide get_stego_key(override) and get_admin_key() accessors.
  - Allow callers to specify a custom env_path for testability.
"""

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv, set_key, dotenv_values

# Default: .env sits next to this file (project root)
_DEFAULT_ENV = Path(__file__).parent / ".env"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_key(env_path: Path, key_name: str) -> str:
    """
    Return the value of *key_name* from the environment.
    If absent, generate a secure random 32-hex-char value, persist it to
    *env_path*, and set it in os.environ.
    """
    value = os.environ.get(key_name)
    if value:
        return value

    # Generate a new cryptographically secure key
    new_value = secrets.token_hex(16)  # 32-character hex string

    # Persist to .env (creates the file if needed)
    set_key(str(env_path), key_name, new_value)
    os.environ[key_name] = new_value

    print(
        f"[env_utils] '{key_name}' not found — auto-generated and saved to {env_path}"
    )
    return new_value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_env(env_path: str = None) -> None:
    """
    Load .env file and ensure both STEGO_SECRET_KEY and ADMIN_KEY are set.

    Priority for each key:
      1. Already in os.environ (e.g. injected by a parent process or test).
      2. Present in the .env file.
      3. Auto-generated (written back to .env).

    Args:
        env_path: Optional override path to the .env file (useful in tests).
    """
    path = Path(env_path) if env_path else _DEFAULT_ENV

    # override=False: existing os.environ values win over .env file values.
    # This ensures CLI --env injection in tests is respected.
    if path.exists():
        load_dotenv(dotenv_path=str(path), override=False)

    _ensure_key(path, "STEGO_SECRET_KEY")
    _ensure_key(path, "ADMIN_KEY")


def get_stego_key(override: str = None, env_path: str = None) -> str:
    """
    Return the active stego key.

    Priority: CLI override > STEGO_SECRET_KEY in .env > auto-generated.

    Args:
        override:  Optional key string from --key CLI flag.
        env_path:  Optional path to a custom .env file (for tests).
    """
    if override:
        return override
    load_env(env_path)
    return os.environ["STEGO_SECRET_KEY"]


def get_admin_key(env_path: str = None) -> str:
    """
    Return the ADMIN_KEY from the environment.

    Args:
        env_path: Optional path to a custom .env file (for tests).
    """
    load_env(env_path)
    return os.environ.get("ADMIN_KEY", "")
