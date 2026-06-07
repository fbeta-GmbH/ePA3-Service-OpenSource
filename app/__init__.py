"""
Application package initialization.

This module sets the OPENSSL_CONF environment variable to ensure that the application uses the correct OpenSSL configuration for TLS connections. 
It also loads environment variables from a .env file located in the config directory. The path to the config directory can be overridden by setting the USER_CONFIG_DIR environment variable.
"""

import os
from pathlib import Path
import dotenv

# --- Constants ---
_APP_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _APP_DIR.parent

_OPENSSL_CONFIG = _APP_DIR / "runtime_config" / "openssl.cnf"
_DEFAULT_USER_CONFIG_DIR = _PROJECT_ROOT / "config"

# --- Directory setup ---
TEMP_DIR: Path = _APP_DIR / "tmp"
DATA_DIR: Path = _APP_DIR / "data"
USER_CONFIG_DIR: Path = Path(os.environ.get("USER_CONFIG_DIR", _DEFAULT_USER_CONFIG_DIR))

def _ensure_openssl_conf() -> None:
    if not _OPENSSL_CONFIG.is_file():
        raise RuntimeError(f"OpenSSL config file not found: {_OPENSSL_CONFIG}")

    os.environ["OPENSSL_CONF"] = str(_OPENSSL_CONFIG)

def _load_env(user_config_dir: Path):
    user_config_file = user_config_dir / ".env"

    if not user_config_file.is_file():
        raise RuntimeError(f"User config file not found: {user_config_file}")
    
    dotenv.load_dotenv(user_config_file)

_ensure_openssl_conf()
_load_env(USER_CONFIG_DIR)

