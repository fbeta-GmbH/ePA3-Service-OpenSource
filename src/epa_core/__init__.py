"""Shared ePA protocol implementation.

Importing :mod:`epa_core` itself performs no network access and does not load a .env file.
Applications should call :func:`bootstrap_environment` before importing runtime modules that
consume environment configuration.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent
TEMP_DIR: Path = Path(os.environ.get("EPA_TEMP_DIR", _PACKAGE_DIR / "tmp"))

_OPENSSL_CONFIG = _PACKAGE_DIR / "runtime_config" / "openssl.cnf"

DATA_DIR: Path = _PACKAGE_DIR / "data"
_DEFAULT_USER_CONFIG_DIR: Path = Path(os.environ.get("USER_CONFIG_DIR", _PROJECT_ROOT / "config"))

def _ensure_openssl_conf() -> None:
    if not _OPENSSL_CONFIG.is_file():
        raise RuntimeError(f"OpenSSL config file not found: {_OPENSSL_CONFIG}")

    os.environ["OPENSSL_CONF"] = str(_OPENSSL_CONFIG)

_ensure_openssl_conf()

def bootstrap_environment(user_config_dir: str | Path | None = None, *, require_env_file: bool = True) -> Path:
    """Configure OpenSSL and load the application's .env file explicitly."""
    from epa_core.runtime_config.constants import Config

    config_dir = Path(user_config_dir) if user_config_dir is not None else _DEFAULT_USER_CONFIG_DIR

    env_file = config_dir / ".env"
    
    if env_file.is_file():
        load_dotenv(env_file)
    elif require_env_file:
        raise RuntimeError(f"User config file not found: {env_file}")

    Config.init(config_dir, TEMP_DIR, DATA_DIR)
    return config_dir

__all__ = ["bootstrap_environment", "__version__"]

__version__ = "2.0.0.dev1"
