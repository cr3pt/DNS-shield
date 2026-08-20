"""One-off importer: bring settings over from an existing AdGuard Home
`AdGuardHome.yaml` into a DNS-shield config (written out as YAML here;
DNS-shield's live config actually lives in a database - see the printed
instructions at the end for how to apply the result).

    python -m app.import_adguard /path/to/AdGuardHome.yaml

Imported: filter (blocklist) subscriptions, whitelist filter subscriptions,
user_rules (both "||domain^" block rules and "@@||domain^" exceptions),
upstream resolvers (including tls:// and https:// upstreams - converted to
DNS-shield's dot:///doh:// syntax), listen address/port, blocking mode, and
per-client "ids" (IPs/CIDRs) from clients.persistent -> DNS-shield's
client_groups (matching AdGuard's own field name for that: `ids`).

Deliberately NOT imported - there is no DNS-shield equivalent, or nothing
safe to carry over automatically (see the printed summary for specifics
on your file):
  - Web UI username/password: AdGuard stores a bcrypt hash, which cannot
    be turned back into the plaintext DNS-shield's basic-auth needs.
  - Parental control / Safe Browsing / Safe Search: these are exactly the
    AdGuard-cloud-calling features DNS-shield exists to avoid.
  - DHCP server, TLS/HTTPS termination, per-client "blocked_services".

This only ever reads the two local YAML files you point it at and writes
one output file - no network access, nothing sent anywhere.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

from app.blocklist import _parse_line

_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(ns|us|µs|ms|s|m|h)")
_DURATION_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}


def parse_go_duration(value: Any) -> float | None:
    """Parse a Go-style duration string ("10s", "1m30s") into seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    total = 0.0
    matched = False
    for amount, unit in _DURATION_RE.findall(value):
        total += float(amount) * _DURATION_UNITS[unit]
        matched = True
    return total if matched else None


def convert_upstream(entry: str) -> tuple[str | None, str | None]:
    """Returns (converted_entry_or_None, warning_or_None)."""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None, None

    if entry.startswith("[/"):
        # Per-domain upstream routing ("[/example.com/]1.2.3.4") - not
        # supported, fall back to just the upstream part.
        _, _, rest = entry.partition("]")
        entry = rest.strip()
        if not entry:
            return None, "could not parse per-domain upstream line, skipped"

    if entry.startswith("tls://"):
        return "dot://" + entry[len("tls://") :], None
    if entry.startswith("https://"):
        return entry, None
    if entry.startswith(("quic://", "h3://", "sdns://")):
        return None, f"unsupported upstream scheme, skipped: {entry!r}"
    if entry.startswith("udp://"):
        return entry[len("udp://") :], None
    if entry.startswith("tcp://"):
        return entry[len("tcp://") :], None
    return entry, None  # plain "ip" or "ip:port"


def convert_blocking_mode(dns_cfg: dict) -> tuple[str, str, str, list[str]]:
    warnings: list[str] = []
    mode = dns_cfg.get("blocking_mode", "default")

    if mode == "nxdomain":
        block_mode = "nxdomain"
    elif mode == "refused":
        block_mode = "nxdomain"
        warnings.append("blocking_mode 'refused' has no DNS-shield equivalent; using nxdomain instead")
    else:
        block_mode = "null_ip"
        if mode not in ("default", "null_ip", "custom_ip"):
            warnings.append(f"unrecognized blocking_mode {mode!r}; defaulting to null_ip")

    blocked_ipv4 = dns_cfg.get("blocking_ipv4") or "0.0.0.0"
    blocked_ipv6 = dns_cfg.get("blocking_ipv6") or "::"
    return block_mode, blocked_ipv4, blocked_ipv6, warnings


def convert_filters(filters: list[dict] | None) -> list[dict]:
    result = []
    for entry in filters or []:
        url = entry.get("url")
        if not url:
            continue
        name = entry.get("name") or url
        result.append({"name": name, "url": url, "enabled": bool(entry.get("enabled", True))})
    return result


def convert_user_rules(rules: list[str] | None) -> tuple[list[str], list[str], list[str]]:
    allow: list[str] = []
    deny: list[str] = []
    skipped: list[str] = []
    for raw in rules or []:
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if line.startswith("#") and not line.startswith("##"):
            continue  # "#" alone is a comment; "##" is an (unsupported) cosmetic rule
        if line.startswith("@@"):
            domain = _parse_line(line[2:])
            (allow if domain else skipped).append(domain or raw)
            continue
        domain = _parse_line(line)
        (deny if domain else skipped).append(domain or raw)
    return allow, deny, skipped


def _looks_like_ip_or_cidr(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def convert_clients(clients_cfg: dict | None) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    groups: list[dict] = []
    persistent = (clients_cfg or {}).get("persistent") or []

    for client in persistent:
        name = client.get("name") or "Unnamed client"
        ids = client.get("ids") or []
        match = [cid for cid in ids if _looks_like_ip_or_cidr(cid)]
        skipped_ids = [cid for cid in ids if cid not in match]
        for cid in skipped_ids:
            warnings.append(
                f"client {name!r}: id {cid!r} is not an IP/CIDR (MAC address or client ID?) - "
                "DNS-shield only matches clients by IP/CIDR, skipped"
            )
        if not match:
            warnings.append(f"client {name!r}: no usable IP/CIDR ids found, group not imported")
            continue

        groups.append(
            {
                "name": name,
                "match": match,
                "enabled": bool(client.get("filtering_enabled", True)),
                "allowlist": [],
                "denylist": [],
            }
        )
        if client.get("use_global_settings") is False:
            warnings.append(
                f"client {name!r}: had custom upstreams/safe-browsing/parental settings in AdGuard Home - "
                "only filtering_enabled was imported, the rest has no DNS-shield equivalent"
            )

    return groups, warnings


def convert_dns_settings(adguard: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    dns_cfg = adguard.get("dns") or {}
    out: dict[str, Any] = {}

    bind_hosts = dns_cfg.get("bind_hosts") or ["0.0.0.0"]
    out["listen_address"] = bind_hosts[0]
    if len(bind_hosts) > 1:
        warnings.append(
            f"dns.bind_hosts had {len(bind_hosts)} addresses; DNS-shield listens on one, "
            f"using {bind_hosts[0]!r}"
        )

    out["listen_port"] = dns_cfg.get("port", 53)

    upstreams = []
    for entry in dns_cfg.get("upstream_dns") or []:
        converted, warning = convert_upstream(entry)
        if warning:
            warnings.append(warning)
        if converted:
            upstreams.append(converted)
    if upstreams:
        out["upstreams"] = upstreams
    else:
        warnings.append("no usable dns.upstream_dns entries found; keeping DNS-shield's default upstreams")

    timeout = parse_go_duration(dns_cfg.get("upstream_timeout"))
    if timeout:
        out["upstream_timeout_seconds"] = timeout

    block_mode, blocked_ipv4, blocked_ipv6, mode_warnings = convert_blocking_mode(dns_cfg)
    warnings.extend(mode_warnings)
    out["block_mode"] = block_mode
    out["blocked_ipv4"] = blocked_ipv4
    out["blocked_ipv6"] = blocked_ipv6

    if dns_cfg.get("parental_enabled") or dns_cfg.get("safebrowsing_enabled"):
        warnings.append(
            "parental control / safe browsing were enabled in AdGuard Home - DNS-shield does not "
            "implement these (they work by calling AdGuard's own cloud service, which is exactly "
            "the kind of call this project avoids), not imported"
        )

    return out, warnings


def import_config(adguard: dict, base: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    result = copy.deepcopy(base)

    dns_settings, dns_warnings = convert_dns_settings(adguard)
    warnings.extend(dns_warnings)
    result.setdefault("dns", {}).update(dns_settings)

    sources = convert_filters(adguard.get("filters"))
    if sources:
        result.setdefault("blocklists", {})["sources"] = sources

    allow_sources = convert_filters(adguard.get("whitelist_filters"))
    if allow_sources:
        result.setdefault("blocklists", {})["allow_sources"] = allow_sources

    allow, deny, skipped_rules = convert_user_rules(adguard.get("user_rules"))
    if allow:
        result["allowlist"] = sorted(set(result.get("allowlist") or []) | set(allow))
    if deny:
        result["denylist"] = sorted(set(result.get("denylist") or []) | set(deny))
    if skipped_rules:
        sample = ", ".join(repr(r) for r in skipped_rules[:5])
        warnings.append(
            f"{len(skipped_rules)} user_rules line(s) used syntax DNS-shield can't parse "
            f"(regex/cosmetic rules, $options, etc.) and were skipped, e.g.: {sample}"
        )

    groups, group_warnings = convert_clients(adguard.get("clients"))
    warnings.extend(group_warnings)
    if groups:
        result["client_groups"] = groups

    warnings.append(
        "NOT imported: web UI username/password - AdGuard stores a bcrypt hash that can't be "
        "reversed into DNS-shield's plaintext basic-auth config. Set web.username/web.password yourself."
    )
    if (adguard.get("dhcp") or {}).get("enabled"):
        warnings.append("NOT imported: DHCP was enabled in AdGuard Home; DNS-shield has no DHCP server")
    if (adguard.get("tls") or {}).get("enabled"):
        warnings.append(
            "NOT imported: TLS/HTTPS termination settings; DNS-shield's web UI is plain HTTP, "
            "put a reverse proxy in front if you need TLS"
        )

    return result, warnings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("adguard_config", type=Path, help="Path to AdGuard Home's AdGuardHome.yaml")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Where to write the imported config (default: <adguard dir>/dnsshield-config.imported.yaml). "
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

    with open(args.adguard_config, "r", encoding="utf-8") as fh:
        adguard = yaml.safe_load(fh) or {}

    base_path = args.base or (Path(__file__).resolve().parent.parent / "config" / "config.example.yaml")
    with open(base_path, "r", encoding="utf-8") as fh:
        base = yaml.safe_load(fh) or {}

    result, warnings = import_config(adguard, base)

    output_path = args.output or (args.adguard_config.parent / "dnsshield-config.imported.yaml")
    with open(output_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(result, fh, sort_keys=False)

    blocklists = result.get("blocklists", {})
    print(f"Wrote imported config to: {output_path}\n")
    print(f"  blocklist sources:   {len(blocklists.get('sources', []))}")
    print(f"  allow-list sources:  {len(blocklists.get('allow_sources', []))}")
    print(f"  allowlist domains:   {len(result.get('allowlist', []))}")
    print(f"  denylist domains:    {len(result.get('denylist', []))}")
    print(f"  client groups:       {len(result.get('client_groups', []))}")
    print(f"  upstreams:           {result.get('dns', {}).get('upstreams')}")

    if warnings:
        print(f"\n{len(warnings)} note(s) - review before using this config:")
        for warning in warnings:
            print(f"  - {warning}")

    print(
        f"\nReview {output_path}, then apply it. DNS-shield's live config lives in a database "
        "(data/config.db), seeded once from data/config.backup.yaml the first time it's opened - "
        "so how you apply this depends on whether that database already exists:\n"
        f"  First-time setup (no data/config.db yet):\n"
        f"    cp {output_path} ./data/config.backup.yaml   # then start the container as usual\n"
        f"  Existing instance (data/config.db already exists):\n"
        f"    docker compose down\n"
        f"    cp {output_path} ./data/config.backup.yaml\n"
        f"    rm ./data/config.db ./data/config.db-wal ./data/config.db-shm\n"
        f"    docker compose up -d\n"
        f"    (re-run this importer with -b ./data/config.backup.yaml as the base first if you want "
        f"to keep settings you've already changed from the dashboard, like your web password.)\n\n"
        "Remember to set web.username/web.password yourself from the dashboard's Settings section - "
        "they were NOT imported."
    )


if __name__ == "__main__":
    main()
