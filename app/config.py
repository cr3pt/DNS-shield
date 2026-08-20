"""Configuration loading/saving.

The config file is plain YAML. On first start it is bootstrapped from
config/config.example.yaml into the writable data directory, and from
then on it is the single source of truth: the web UI mutates it in place
(via update_yaml) and the DNS/blocklist components read it back.
"""

from __future__ import annotations

import copy
import os
import shutil
import threading
from pathlib import Path
from typing import Any

import yaml

APP_DIR = Path(__file__).resolve().parent
REPO_DIR = APP_DIR.parent
EXAMPLE_CONFIG = REPO_DIR / "config" / "config.example.yaml"

_LOCK = threading.Lock()


def _default_config_path() -> Path:
    return Path(os.environ.get("DNSSHIELD_CONFIG", "/data/config.yaml"))


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load config from disk, seeding it from the example on first run."""
    path = path or _default_config_path()
    with _LOCK:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(EXAMPLE_CONFIG, path)
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    return data


def save_config(data: dict[str, Any], path: Path | None = None) -> None:
    path = path or _default_config_path()
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, sort_keys=False)
        tmp_path.replace(path)


class ConfigStore:
    """Thread-safe in-process view of the config file.

    Every mutation is written straight back to disk so state survives a
    container restart without needing a separate database.
    """

    def __init__(self, path: Path | None = None):
        self.path = path or _default_config_path()
        self._data = load_config(self.path)
        self._lock = threading.RLock()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def get(self, *keys: str, default: Any = None) -> Any:
        with self._lock:
            node: Any = self._data
            for key in keys:
                if not isinstance(node, dict) or key not in node:
                    return default
                node = node[key]
            return node

    def mutate(self, fn) -> Any:
        """Apply fn(data) under the lock, persist, and return fn's result."""
        with self._lock:
            result = fn(self._data)
            save_config(self._data, self.path)
            return result

    def reload(self) -> None:
        with self._lock:
            self._data = load_config(self.path)
