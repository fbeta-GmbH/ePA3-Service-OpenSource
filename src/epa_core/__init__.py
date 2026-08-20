"""Shared ePA protocol implementation.

Importing :mod:`epa_core` itself performs no network access and does not load a .env file.
Applications should call :func:`bootstrap_environment` before importing runtime modules that
consume environment configuration.
"""
from pathlib import Path
import os

_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent
TEMP_DIR: Path = Path(os.environ.get("EPA_TEMP_DIR", _PACKAGE_DIR / "tmp"))
DATA_DIR: Path = _PACKAGE_DIR / "data"
USER_CONFIG_DIR: Path = Path(os.environ.get("USER_CONFIG_DIR", _PROJECT_ROOT / "config"))


def bootstrap_environment(user_config_dir: str | Path | None = None, *, require_env_file: bool = True) -> Path:
    """Configure OpenSSL and load the application's .env file explicitly."""
    from dotenv import load_dotenv

    config_dir = Path(user_config_dir) if user_config_dir is not None else USER_CONFIG_DIR
    openssl_config = _PACKAGE_DIR / "runtime_config" / "openssl.cnf"
    if not openssl_config.is_file():
        raise RuntimeError(f"OpenSSL config file not found: {openssl_config}")
    os.environ["OPENSSL_CONF"] = str(openssl_config)

    env_file = config_dir / ".env"
    if env_file.is_file():
        load_dotenv(env_file)
    elif require_env_file:
        raise RuntimeError(f"User config file not found: {env_file}")
    return config_dir

__all__ = ["DATA_DIR", "TEMP_DIR", "USER_CONFIG_DIR", "bootstrap_environment", "__version__"]

__version__ = "2.0.0.dev2"
