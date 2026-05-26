import os
import dotenv

_APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# check if env variable for user config dir is set, if not use default path
if "USER_CONFIG_DIR" in os.environ:
    USER_CONFIG_DIR = os.environ["USER_CONFIG_DIR"]
else:
    USER_CONFIG_DIR = os.path.join(_APP_ROOT, "config")

_CONFIG_LOADED = False
def load_env():
    global _CONFIG_LOADED
    if not _CONFIG_LOADED:
        dotenv.load_dotenv(os.path.join(USER_CONFIG_DIR, ".env"))
        _CONFIG_LOADED = True