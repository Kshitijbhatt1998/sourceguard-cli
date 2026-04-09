import os
import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".sourceguard"
CONFIG_FILE = CONFIG_DIR / "config.json"

class ConfigManager:
    @staticmethod
    def ensure_config_dir():
        if not CONFIG_DIR.exists():
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            # On Unix-like systems, set directory permissions to 700
            if os.name != 'nt':
                os.chmod(CONFIG_DIR, 0o700)

    @classmethod
    def save_config(cls, api_key: str, base_url: str = "http://localhost:8000"):
        cls.ensure_config_dir()
        config = {
            "api_key": api_key,
            "base_url": base_url
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        
        # Set file permissions to 600
        if os.name != 'nt':
            os.chmod(CONFIG_FILE, 0o600)

    @classmethod
    def load_config(cls) -> dict:
        if not CONFIG_FILE.exists():
            return {}
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    @classmethod
    def delete_config(cls):
        if CONFIG_FILE.exists():
            os.remove(CONFIG_FILE)

    @staticmethod
    def mask_key(key: str) -> str:
        if not key:
            return "None"
        if len(key) <= 8:
            return "*" * len(key)
        return f"{key[:3]}..." + "*" * 8 + f"{key[-4:]}"
