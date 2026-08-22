"""Password hashing.

Every stored password is a bcrypt hash - nothing is ever kept in plain
text once app.users has migrated it. This module is a thin, dependency-
isolating wrapper so the rest of the app never imports bcrypt directly.
"""

from __future__ import annotations

import bcrypt


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # Not a valid bcrypt hash (e.g. a pre-migration plain-text value
        # slipped through some other path) - never treat that as a match.
        return False
