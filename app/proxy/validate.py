from __future__ import annotations

import re

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$"
)
UPSTREAM_RE = re.compile(
    r"^https?://[a-zA-Z0-9.-]+(:[0-9]{1,5})?(/[a-zA-Z0-9\-._~%!$&'()*+=:@/]*)?$"
)
PATH_RE = re.compile(r"^/[a-zA-Z0-9\-._~%!$&'()*+=:@/]*$")
REDIRECT_CODES = (301, 302, 307, 308)


class ValidationError(Exception):
    pass


def assert_hostname(value: str, field: str = "domain") -> str:
    if not isinstance(value, str) or not HOSTNAME_RE.match(value):
        raise ValidationError(f'Invalid {field}: "{value}"')
    return value.lower()


def assert_upstream(value: str) -> str:
    if not isinstance(value, str) or not UPSTREAM_RE.match(value):
        raise ValidationError(f'Invalid upstream target: "{value}". Use http(s)://host:port')
    return value


def assert_path(value: str) -> str:
    if not isinstance(value, str) or not PATH_RE.match(value):
        raise ValidationError(f'Invalid path: "{value}". Must start with "/" and contain no whitespace or semicolons')
    return value


def assert_redirect_code(value) -> int:
    try:
        code = int(value)
    except (TypeError, ValueError):
        code = None
    if code not in REDIRECT_CODES:
        raise ValidationError(f'Invalid redirect code: "{value}". Allowed: {", ".join(map(str, REDIRECT_CODES))}')
    return code


def assert_redirect_target(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048 or re.search(r'[\r\n;{}<>"\']', value):
        raise ValidationError(f'Invalid redirect target: "{value}"')
    return value


def assert_file_path(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or re.search(r"[\r\n;{}]", value) or not value.startswith("/"):
        raise ValidationError(f'Invalid file path ({field}): "{value}"')
    return value
