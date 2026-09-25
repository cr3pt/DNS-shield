from __future__ import annotations

import time


def ensure_learning_started(config_store, section: str, key: str = "learning_started_at") -> float:
    started = config_store.get(section, key, default=None)
    if started is not None:
        return float(started)

    now = time.time()

    def _mutate(data):
        data.setdefault(section, {})[key] = now

    config_store.mutate(_mutate)
    return now


def learning_elapsed(
    config_store, section: str, days_key: str, started_key: str = "learning_started_at", now: float | None = None
) -> bool:
    now = time.time() if now is None else now
    started = ensure_learning_started(config_store, section, started_key)
    days = float(config_store.get(section, days_key, default=7) or 7)
    return now >= started + days * 86400


def reset_learning(config_store, section: str, key: str = "learning_started_at") -> None:
    def _mutate(data):
        data.setdefault(section, {})[key] = None

    config_store.mutate(_mutate)
