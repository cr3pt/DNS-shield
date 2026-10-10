# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

from datetime import datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _parse_hhmm(value: str) -> time | None:
    try:
        hh, mm = value.split(":", 1)
        return time(int(hh), int(mm))
    except (ValueError, AttributeError, TypeError):
        return None


def _now(tz_name: str | None) -> datetime:
    if tz_name:
        try:
            return datetime.now(ZoneInfo(tz_name))
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            pass
    return datetime.now().astimezone()


def is_schedule_blocked(schedule: dict | None, now: datetime | None = None) -> bool:
    if not schedule or not schedule.get("enabled", False):
        return False
    windows = schedule.get("windows") or []
    if not windows:
        return False

    moment = now if now is not None else _now(schedule.get("timezone"))
    weekday = moment.weekday()
    current_time = moment.time()

    for window in windows:
        days = window.get("days") or []
        if not days:
            continue
        start = _parse_hhmm(window.get("start", ""))
        end = _parse_hhmm(window.get("end", ""))
        if start is None or end is None or start == end:
            continue

        if start < end:
            if weekday in days and start <= current_time < end:
                return True
        else:
            if weekday in days and current_time >= start:
                return True
            prev_day = (weekday - 1) % 7
            if prev_day in days and current_time < end:
                return True

    return False
