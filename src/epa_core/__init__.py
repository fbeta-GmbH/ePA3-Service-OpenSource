"""Shared ePA protocol implementation.

OPENSSL_CONF is configured immediately when epa_core is imported.

Call bootstrap_environment() before using runtime components.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

__version__ = "2.0.0.dev2"

# -- Package paths ---------------------------------

_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent

_OPENSSL_CONFIG = _PACKAGE_DIR / "runtime_config" / "openssl.cnf"

DATA_DIR = _PACKAGE_DIR / "data"

# -- OpenSSL initialization ------------------------

def _ensure_openssl_conf() -> None:
    """Set the mandatory OpenSSL configuration."""
    if not _OPENSSL_CONFIG.is_file():
        raise RuntimeError(f"OpenSSL config file not found: {_OPENSSL_CONFIG}")

    os.environ["OPENSSL_CONF"] = str(_OPENSSL_CONFIG)

# Must execute before importing runtime dependencies.
_ensure_openssl_conf()


# -- Application bootstrap ------------------------

def bootstrap_environment(user_config_dir: str | Path | None = None, *, require_env_file: bool = True) -> Path:
    """Load the user's environment and initialize ePA Core."""
    from epa_core.runtime_config.constants import (init_config)

    config_dir = Path(
        user_config_dir
        if user_config_dir is not None
        else os.environ.get("USER_CONFIG_DIR", _PROJECT_ROOT / "config")
    ).resolve()

    env_file = config_dir / ".env"
    if env_file.is_file():
        load_dotenv(env_file, override=False)
    elif require_env_file:
        raise FileNotFoundError(f"User config file not found: {env_file}")

    temp_dir = Path(os.environ.get("EPA_TEMP_DIR", _PACKAGE_DIR / "tmp")).resolve()

    # Build and return the complete application config
    init_config(user_config_dir=config_dir, temp_dir=temp_dir, data_dir=DATA_DIR)
    return config_dir


__all__ = [
    "bootstrap_environment",
    "__version__",
]
