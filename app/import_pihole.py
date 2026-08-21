"""One-off importer: bring your Pi-hole blocklist/allow/deny/client data
over from a `gravity.db` export into a DNS-shield config.

Pi-hole keeps its list/domain/client data in a single SQLite database,
`gravity.db` - included in a Pi-hole "Teleporter" backup, or copyable
directly off the Pi-hole host (`/etc/pihole/gravity.db`). Upload that file
in the dashboard's Settings -> Import tab, or run this the same way as
import_adguard.py:

    python -m app.import_pihole /path/to/gravity.db

Imported: `adlist` (blocklist subscription URLs - and allow-list URLs too,
on a gravity.db version new enough to have `adlist.type`), enabled
`domainlist` exact-match entries (type 0 allow / type 1 deny), enabled
`domainlist` regex-deny entries (type 3 - mapped to DNS-shield's
experimental `denylist_regex`, which also gets turned on for you, since an
imported pattern nothing ever checks isn't useful), and `client` IPs (as
client_groups with no group-specific list - see below).

Deliberately NOT imported - not present in gravity.db, or nothing safe to
carry over automatically:
  - Upstream DNS servers, listen address/port, blocking mode: these live
    in Pi-hole's setupVars.conf / pihole.toml / dnsmasq config, not
    gravity.db, and this importer only ever reads the one file you give it.
  - `domainlist` regex ALLOW entries (type 2): DNS-shield has no regex
    allowlist mechanism, only a regex denylist.
  - Per-client/per-group list assignments: gravity.db's group-membership
    tables vary across Pi-hole versions, so imported clients get
    DNS-shield's default (global) policy - not whichever specific groups
    they belonged to in Pi-hole. Recreate anything client-specific by hand
    in client_groups afterwards.
  - Web UI username/password: same reasoning as the AdGuard Home importer -
    Pi-hole doesn't store a reversible plaintext password either. Set
    web.username/web.password yourself from the dashboard.
"""

from __future__ import annotations

import argparse
import copy
import re
import sqlite3
from pathlib import Path
from typing import Any

import yaml

_REGEX_MODIFIER_RE = re.compile(r"\s*;\s*\w+\s*=.*$")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.DatabaseError:
        return set()
    return {row[1] for row in rows}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def convert_adlists(conn: sqlite3.Connection) -> tuple[list[dict], list[dict], list[str]]:
    warnings: list[str] = []
    if not _table_exists(conn, "adlist"):
        return [], [], ["gravity.db has no 'adlist' table - no blocklist sources to import"]

    columns = _table_columns(conn, "adlist")
    has_type = "type" in columns  # newer gravity.db: 0 = block, 1 = allow
    select = "address, enabled" + (", type" if has_type else "")
    rows = conn.execute(f"SELECT {select} FROM adlist").fetchall()

    sources: list[dict] = []
    allow_sources: list[dict] = []
    for row in rows:
        address = row[0]
        if not address:
            continue
        entry = {"name": address, "url": address, "enabled": bool(row[1])}
        is_allow = has_type and len(row) > 2 and row[2] == 1
        (allow_sources if is_allow else sources).append(entry)

    return sources, allow_sources, warnings


def convert_domainlist(conn: sqlite3.Connection) -> tuple[list[str], list[str], list[str], list[str]]:
    """Returns (allowlist, denylist, denylist_regex, warnings)."""
    warnings: list[str] = []
    if not _table_exists(conn, "domainlist"):
        return [], [], [], ["gravity.db has no 'domainlist' table - no allow/deny domains to import"]

    rows = conn.execute("SELECT domain, type, enabled FROM domainlist").fetchall()

    allowlist: list[str] = []
    denylist: list[str] = []
    denylist_regex: list[str] = []
    skipped_disabled = 0
    skipped_regex_allow = 0
    skipped_invalid_regex: list[str] = []

    for domain, list_type, enabled in rows:
        if not domain:
            continue
        if not enabled:
            skipped_disabled += 1
            continue

        if list_type == 0:
            allowlist.append(domain.strip().lower())
        elif list_type == 1:
            denylist.append(domain.strip().lower())
        elif list_type == 2:
            skipped_regex_allow += 1
        elif list_type == 3:
            pattern = _REGEX_MODIFIER_RE.sub("", domain).strip()
            try:
                re.compile(pattern)
            except re.error:
                skipped_invalid_regex.append(domain)
                continue
            denylist_regex.append(pattern)

    if skipped_disabled:
        warnings.append(f"{skipped_disabled} disabled domainlist entr(y/ies) in gravity.db were skipped")
    if skipped_regex_allow:
        warnings.append(
            f"{skipped_regex_allow} regex ALLOW entr(y/ies) skipped - DNS-shield has no regex "
            "allowlist, only a regex denylist"
        )
    if skipped_invalid_regex:
        sample = ", ".join(repr(p) for p in skipped_invalid_regex[:5])
        warnings.append(
            f"{len(skipped_invalid_regex)} regex deny entr(y/ies) didn't compile as a Python regex "
            f"and were skipped, e.g.: {sample}"
        )

    return allowlist, denylist, denylist_regex, warnings


def convert_clients(conn: sqlite3.Connection) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    if not _table_exists(conn, "client"):
        return [], []

    rows = conn.execute("SELECT ip, comment FROM client").fetchall()
    groups: list[dict] = []
    for ip, comment in rows:
        if not ip:
            continue
        groups.append(
            {
                "name": (comment or ip).strip(),
                "match": [ip.strip()],
                "enabled": True,
                "allowlist": [],
                "denylist": [],
            }
        )

    if groups:
        warnings.append(
            f"{len(groups)} client(s) imported as client_groups with no group-specific allow/deny - "
            "gravity.db's group-membership tables vary across Pi-hole versions, so this only carries "
            "over the client IP, not which Pi-hole group(s) it belonged to"
        )
    return groups, warnings


def import_config(db_path: Path, base: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    result = copy.deepcopy(base)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        sources, allow_sources, source_warnings = convert_adlists(conn)
        warnings.extend(source_warnings)
        if sources:
            result.setdefault("blocklists", {})["sources"] = sources
        if allow_sources:
            result.setdefault("blocklists", {})["allow_sources"] = allow_sources

        allow, deny, deny_regex, domain_warnings = convert_domainlist(conn)
        warnings.extend(domain_warnings)
        if allow:
            result["allowlist"] = sorted(set(result.get("allowlist") or []) | set(allow))
        if deny:
            result["denylist"] = sorted(set(result.get("denylist") or []) | set(deny))
        if deny_regex:
            result["denylist_regex"] = sorted(set(result.get("denylist_regex") or []) | set(deny_regex))
            result.setdefault("dns", {})["regex_denylist_enabled"] = True
            warnings.append(
                f"{len(deny_regex)} regex deny pattern(s) imported and dns.regex_denylist_enabled "
                "turned on - this checks every query against every pattern (see README); disable it "
                "again in Settings -> DNS if that's not what you want"
            )

        groups, client_warnings = convert_clients(conn)
        warnings.extend(client_warnings)
        if groups:
            result["client_groups"] = groups
    finally:
        conn.close()

    warnings.append(
        "NOT imported: upstream DNS servers, listen address/port, blocking mode - these live in "
        "Pi-hole's setupVars.conf/pihole.toml/dnsmasq config, not gravity.db. Set dns.upstreams and "
        "the rest yourself."
    )
    warnings.append(
        "NOT imported: web UI username/password - set web.username/web.password yourself from the "
        "dashboard."
    )

    return result, warnings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("gravity_db", type=Path, help="Path to Pi-hole's gravity.db")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Where to write the imported config (default: <gravity.db dir>/dnsshield-config.imported.yaml). "
        "Never overwrites your live config automatically.",
    )
    parser.add_argument(
        "-b",
        "--base",
        type=Path,
        default=None,
        help="Existing DNS-shield config.yaml to merge into (default: the bundled config.example.yaml)",
    )
    args = parser.parse_args()

    base_path = args.base or (Path(__file__).resolve().parent.parent / "config" / "config.example.yaml")
    with open(base_path, "r", encoding="utf-8") as fh:
        base = yaml.safe_load(fh) or {}

    result, warnings = import_config(args.gravity_db, base)

    output_path = args.output or (args.gravity_db.parent / "dnsshield-config.imported.yaml")
    with open(output_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(result, fh, sort_keys=False)

    blocklists = result.get("blocklists", {})
    print(f"Wrote imported config to: {output_path}\n")
    print(f"  blocklist sources:   {len(blocklists.get('sources', []))}")
    print(f"  allow-list sources:  {len(blocklists.get('allow_sources', []))}")
    print(f"  allowlist domains:   {len(result.get('allowlist', []))}")
    print(f"  denylist domains:    {len(result.get('denylist', []))}")
    print(f"  denylist regex:      {len(result.get('denylist_regex', []))}")
    print(f"  client groups:       {len(result.get('client_groups', []))}")

    if warnings:
        print(f"\n{len(warnings)} note(s) - review before using this config:")
        for warning in warnings:
            print(f"  - {warning}")

    print(
        f"\nReview {output_path}, then apply it - see import_adguard.py's --help or the README for "
        "how DNS-shield's config.db/config.backup.yaml apply flow works; it's the same either way."
    )


if __name__ == "__main__":
    main()
