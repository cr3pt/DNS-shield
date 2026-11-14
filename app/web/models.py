# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Request bodies (pydantic models) accepted by the web API."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from app.domain_suffix import normalize_domain
from app.netmatch import normalize_client_patterns


class BlocklistSourceIn(BaseModel):
    name: str
    url: str
    enabled: bool = True


class DomainIn(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return normalize_domain(value)


class TyposquatFpIn(BaseModel):
    domain: str
    protected: str


class RebindingFpIn(BaseModel):
    domain: str
    ip: str


class ThreatIntelFpIn(BaseModel):
    target: str
    verdict: str


class ValueIn(BaseModel):
    value: str


class RegexPatternIn(BaseModel):
    pattern: str


_GROUP_NAME_MAX_LENGTH = 255


def _clean_group_name(value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value or ""):
        raise ValueError("Group name can't contain control characters")
    name = " ".join((value or "").split())
    if not name:
        raise ValueError("Group name can't be empty")
    if len(name) > _GROUP_NAME_MAX_LENGTH:
        raise ValueError(f"Group name can be at most {_GROUP_NAME_MAX_LENGTH} characters")
    return name


class ClientGroupIn(BaseModel):
    name: str
    match: list[str] = []

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _clean_group_name(value)

    @field_validator("match")
    @classmethod
    def _validate_match(cls, value: list[str]) -> list[str]:
        return normalize_client_patterns(value)

    enabled: bool = True
    allowlist: list[str] = []
    denylist: list[str] = []
    upstreams: list[str] = []
    blocklist_sources: list[dict[str, Any]] = []
    safe_search: bool | None = None
    schedule: dict[str, Any] | None = None
    blocked_services: list[str] = []

    @field_validator("blocked_services")
    @classmethod
    def _validate_services(cls, value: list[str]) -> list[str]:
        return _validate_service_ids(value)


def _validate_service_ids(value: list[str]) -> list[str]:
    from app.services import SERVICES, known_ids

    unknown = sorted({str(v).strip().lower() for v in value} - set(SERVICES))
    if unknown:
        raise ValueError(f"unknown service(s): {', '.join(unknown)}")
    return known_ids(value)


class BlockedServicesIn(BaseModel):
    services: list[str] = []

    @field_validator("services")
    @classmethod
    def _validate(cls, value: list[str]) -> list[str]:
        return _validate_service_ids(value)


class GroupNameIn(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _clean_group_name(value)


class GroupEnabledIn(BaseModel):
    enabled: bool


class GroupMatchIn(BaseModel):
    patterns: list[str] = Field(min_length=1, max_length=200)


class GroupSafeSearchIn(BaseModel):
    safe_search: bool | None = None


class DhcpReservationIn(BaseModel):
    mac: str
    ip: str
    hostname: str | None = None
    dns_servers: list[str] = []
    custom_options: list[dict[str, Any]] = []


class DhcpScopeIn(BaseModel):
    name: str
    enabled: bool = True
    interface: str
    vlan_id: int | None = None
    server_ip: str
    network: str
    pool_start: str
    pool_end: str
    gateway: str = ""
    dns_servers: list[str] = []
    domain_name: str = ""
    lease_seconds: float = 86400
    ntp_servers: list[str] = []
    wins_servers: list[str] = []
    mtu: int | None = None
    tftp_server: str = ""
    bootfile_name: str = ""
    static_routes: list[dict[str, Any]] = []
    excluded_ips: list[str] = []
    custom_options: list[dict[str, Any]] = []
    reservations: list[dict[str, Any]] = []


class DhcpScopePatchIn(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    interface: str | None = None
    vlan_id: int | None = None
    server_ip: str | None = None
    network: str | None = None
    pool_start: str | None = None
    pool_end: str | None = None
    gateway: str | None = None
    dns_servers: list[str] | None = None
    domain_name: str | None = None
    lease_seconds: float | None = None
    ntp_servers: list[str] | None = None
    wins_servers: list[str] | None = None
    mtu: int | None = None
    tftp_server: str | None = None
    bootfile_name: str | None = None
    static_routes: list[dict[str, Any]] | None = None
    excluded_ips: list[str] | None = None
    custom_options: list[dict[str, Any]] | None = None


class DhcpSettingsIn(BaseModel):
    enabled: bool | None = None


class RogueDhcpSettingsIn(BaseModel):
    enabled: bool | None = None
    interfaces: list[str] | None = None
    allowed_server_ips: list[str] | None = None
    check_interval_minutes: float | None = None
    cooldown_minutes: float | None = None


class NewClientDetectionSettingsIn(BaseModel):
    dns_enabled: bool | None = None
    dns_learning_days: float | None = None
    dhcp_enabled: bool | None = None
    dhcp_learning_days: float | None = None


class ProxyRuleIn(BaseModel):
    id: str | None = None
    type: str = "proxy"
    path: str = "/"
    upstream: str | None = None
    websocket: bool = False
    target: str | None = None
    code: int | None = None


class ProxySslIn(BaseModel):
    enabled: bool = False
    cert_path: str | None = None
    key_path: str | None = None


class ProxyDomainIn(BaseModel):
    hostnames: list[str] | str
    rules: list[dict[str, Any]] = []
    enabled: bool | None = None
    force_https: bool = False
    ssl: dict[str, Any] | None = None
    custom_config: str | None = None


class ProxySettingsIn(BaseModel):
    enabled: bool | None = None


class GraphSettingsIn(BaseModel):
    suspicious_zscore: float | None = None
    suspicious_min_degree: int | None = None


class ProxyCertbotIn(BaseModel):
    email: str


class ScheduleWindowIn(BaseModel):
    days: list[int]
    start: str
    end: str


class InternetOffIn(BaseModel):
    # None: until someone turns it back on
    minutes: int | None = Field(default=None, ge=1, le=7 * 24 * 60)


class AllowNowIn(BaseModel):
    minutes: int = Field(ge=1, le=24 * 60)


class GroupScheduleIn(BaseModel):
    enabled: bool = False
    timezone: str = ""
    windows: list[ScheduleWindowIn] = []


class DnsSettingsIn(BaseModel):
    listen_address: str | None = None
    listen_port: int | None = None
    upstream_timeout_seconds: float | None = None
    upstream_strategy: str | None = None
    upstream_stats_window_minutes: float | None = None
    query_case_randomization_enabled: bool | None = None
    strip_ecs: bool | None = None
    edns_padding: bool | None = None
    block_mode: str | None = None
    blocked_ipv4: str | None = None
    blocked_ipv6: str | None = None
    block_ipv6: bool | None = None
    block_non_latin: bool | None = None
    cache_enabled: bool | None = None
    cache_max_entries: int | None = None
    cache_min_ttl_seconds: int | None = None
    cache_max_ttl_seconds: int | None = None
    cache_serve_stale_enabled: bool | None = None
    cache_stale_grace_seconds: int | None = None
    cache_prefetch_enabled: bool | None = None
    cache_prefetch_before_expiry_seconds: int | None = None
    cache_prefetch_min_hits: int | None = None
    resolve_client_names: bool | None = None
    client_names_from_dhcp: bool | None = None
    client_name_resolver: str | None = None
    client_name_cache_seconds: int | None = None
    block_page_enabled: bool | None = None
    block_page_port: int | None = None
    regex_denylist_enabled: bool | None = None
    safe_search_enabled: bool | None = None
    dnssec_enabled: bool | None = None
    dnssec_cache_seconds: float | None = None
    dnssec_validation: str | None = Field(default=None, pattern="^(upstream|local)$")
    dnssec_trust_anchors: list[str] | None = None

    @field_validator("dnssec_trust_anchors")
    @classmethod
    def _validate_trust_anchors(cls, value: list[str] | None) -> list[str] | None:
        if not value:
            return value
        from app.dnssec_validate import _parse_anchors

        cleaned = [line.strip() for line in value if line.strip()]
        try:
            _parse_anchors(cleaned)
        except Exception as exc:
            raise ValueError(f"invalid trust anchor: {exc}") from None
        return cleaned
    typosquat_enabled: bool | None = None
    typosquat_max_distance: int | None = None
    typosquat_cooldown_minutes: float | None = None
    typosquat_action: str | None = None
    typosquat_redirect_ip: str | None = None
    dot_enabled: bool | None = None
    dot_port: int | None = Field(default=None, ge=1, le=65535)
    doq_enabled: bool | None = None
    doq_port: int | None = Field(default=None, ge=1, le=65535)
    rebinding_protection_enabled: bool | None = None
    rebinding_action: str | None = None
    rebinding_exempt_domains: list[str] | None = None
    local_tld_alert_enabled: bool | None = None
    local_tld_list: list[str] | None = None
    local_tld_cooldown_minutes: float | None = None
    query_acl_enabled: bool | None = None
    query_acl_extra_networks: list[str] | None = None
    rate_limit_qps: float | None = Field(default=None, ge=0, le=100000)
    rate_limit_burst: float | None = Field(default=None, ge=0, le=1000000)
    rate_limit_exempt: list[str] | None = None

    @field_validator("rate_limit_exempt")
    @classmethod
    def _validate_rate_limit_exempt(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = []
        for item in value:
            text = str(item).strip()
            if not text:
                continue
            try:
                cleaned.append(str(ipaddress.ip_network(text, strict=False)) if "/" in text else str(ipaddress.ip_address(text)))
            except ValueError:
                raise ValueError(f'"{text}" is not an IP address or CIDR range') from None
        return cleaned


class UpstreamsIn(BaseModel):
    upstreams: list[str]


class DomainUpstreamIn(BaseModel):
    name: str
    domains: list[str] = []
    upstreams: list[str] = []


class RewriteIn(BaseModel):
    name: str
    type: str
    value: str
    ttl: int | None = None


class WebSettingsIn(BaseModel):
    listen_address: str | None = None
    listen_port: int | None = None
    theme: str | None = None
    https_enabled: bool | None = None
    https_cert_path: str | None = None
    https_key_path: str | None = None
    login_max_attempts: int | None = None
    login_lockout_minutes: float | None = None
    public_view_enabled: bool | None = None
    public_url: str | None = None

    @field_validator("public_url")
    @classmethod
    def _validate_public_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return value
        parsed = urlparse(value.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Public URL must look like https://dns.example.lan:3000")
        return f"{parsed.scheme}://{parsed.netloc}"


class ClearSecretIn(BaseModel):
    path: str


class LoginIn(BaseModel):
    username: str
    password: str


class UserPermissionsIn(BaseModel):
    allowed_clients: list[str] = []
    allowed_groups: list[str] = []
    view_threat_intel: bool = False
    view_anomalies: bool = False
    can_block: bool = False
    can_whitelist: bool = False


class UserCreateIn(BaseModel):
    username: str
    password: str
    role: str = "user"
    permissions: UserPermissionsIn | None = None


class UserUpdateIn(BaseModel):
    password: str | None = None
    role: str | None = None
    permissions: UserPermissionsIn | None = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class LanguageIn(BaseModel):
    language: str


class ApiTokenIn(BaseModel):
    name: str


class TotpConfirmIn(BaseModel):
    code: str


class TotpDisableIn(BaseModel):
    password: str


class TotpLoginIn(BaseModel):
    totp_token: str
    code: str


class PasskeyLoginOptionsIn(BaseModel):
    totp_token: str


class PasskeyLoginVerifyIn(BaseModel):
    totp_token: str
    credential: dict[str, Any]


class PasskeyRegisterVerifyIn(BaseModel):
    token: str
    name: str = ""
    credential: dict[str, Any]


class LoggingSettingsIn(BaseModel):
    retention_days: float | None = None
    syslog_enabled: bool | None = None
    syslog_host: str | None = Field(default=None, max_length=253, pattern=r"^[A-Za-z0-9.:_\-\[\]]*$")
    syslog_port: int | None = Field(default=None, ge=1, le=65535)
    syslog_protocol: str | None = Field(default=None, pattern="^(udp|tcp)$")
    syslog_format: str | None = Field(default=None, pattern="^(text|json)$")
    syslog_only_blocked: bool | None = None

    @field_validator("syslog_host")
    @classmethod
    def _strip_brackets(cls, value: str | None) -> str | None:
        return value.strip().strip("[]") if value is not None else None


class BlocklistSettingsIn(BaseModel):
    refresh_interval_hours: float | None = None


class PauseIn(BaseModel):
    seconds: float | None = Field(None, ge=0, le=31 * 86400)


class EnrichmentSettingsIn(BaseModel):
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    greynoise_api_key: str | None = None
    shodan_api_key: str | None = None
    urlhaus_api_key: str | None = None
    rdap_enabled: bool | None = None
    crtsh_enabled: bool | None = None
    ipinfo_enabled: bool | None = None
    ipinfo_api_key: str | None = None
    ai_enabled: bool | None = None
    ai_api_key: str | None = None
    public_enabled: bool | None = None
    local_enabled: bool | None = None
    local_url: str | None = None
    local_api_key: str | None = None
    alert_enabled: bool | None = None
    alert_min_severity: str | None = None
    auto_enrich_enabled: bool | None = None
    auto_enrich_interval_seconds: float | None = None
    auto_enrich_max_per_check: int | None = None


class EnrichIn(BaseModel):
    target: str
    type: str


class AnomalySettingsIn(BaseModel):
    enabled: bool | None = None
    check_interval_minutes: float | None = Field(None, gt=0)
    window_minutes: float | None = Field(None, gt=0)
    min_queries: int | None = None
    blocked_ratio_threshold: float | None = None
    domain_burst_threshold: int | None = None
    domain_burst_min_entropy: float | None = None
    domain_burst_min_label_length: int | None = None
    domain_burst_entropy_fraction: float | None = None
    blocked_domain_burst_threshold: int | None = None
    dns_tunneling_threshold: int | None = None
    dns_tunneling_min_label_length: int | None = None
    dns_tunneling_min_entropy: float | None = None
    subdomain_count_threshold: int | None = None
    ptr_scan_threshold: int | None = None
    cooldown_minutes: float | None = None


class ReanalyzeIn(BaseModel):
    hours: float = Field(gt=0, le=24 * 90)


class AlertRulesSettingsIn(BaseModel):
    check_interval_seconds: float | None = Field(None, gt=0)
    cooldown_minutes: float | None = None


class UrlPingSettingsIn(BaseModel):
    enabled: bool | None = None
    url: str | None = None
    interval_minutes: float | None = None


class NotificationEmailSettingsIn(BaseModel):
    enabled: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_security: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    from_address: str | None = None
    to_addresses: list[str] | None = None
    min_severity: str | None = None


class NotificationWebhookIn(BaseModel):
    name: str | None = None
    type: str | None = None
    enabled: bool | None = None
    url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: str | None = None


class SSOSettingsIn(BaseModel):
    enabled: bool | None = None
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    button_label: str | None = None
    username_claim: str | None = None
    auto_provision: bool | None = None
    default_role: str | None = None


class SyncSettingsIn(BaseModel):
    enabled: bool | None = None
    primary_url: str | None = Field(default=None, max_length=2048)
    token: str | None = Field(default=None, max_length=512)
    interval_seconds: float | None = Field(default=None, ge=30, le=86400)
    verify_tls: bool | None = None
    sections: list[str] | None = None

    @field_validator("primary_url")
    @classmethod
    def _validate_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().rstrip("/")
        if value and urlparse(value).scheme not in ("http", "https"):
            raise ValueError("the primary's URL must start with http:// or https://")
        if value and not urlparse(value).hostname:
            raise ValueError("the primary's URL has no host name")
        return value

    @field_validator("sections")
    @classmethod
    def _validate_sections(cls, value: list[str] | None) -> list[str] | None:
        from app.sync import NEVER_SYNCED

        if value is None:
            return None
        cleaned = [str(v).strip() for v in value if str(v).strip()]
        bad = sorted(set(cleaned) & NEVER_SYNCED)
        if bad:
            raise ValueError(f"these sections are never synced: {', '.join(bad)}")
        return list(dict.fromkeys(cleaned))
