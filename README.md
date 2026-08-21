# DNS-shield

A small, self-hosted, network-wide DNS ad/tracker blocker you run in Docker.
It does the same core job as [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) -
sit as your network's DNS resolver and drop queries to ad/tracker domains -
but with a much smaller, auditable footprint and **no built-in calls to any
third-party cloud service**.

## Screenshots

| Logs | Stats |
| --- | --- |
| ![Query log browser](docs/screenshots/logs.png) | ![Stats tab](docs/screenshots/stats.png) |

| Settings - DNS & upstreams | Settings - client groups |
| --- | --- |
| ![DNS settings](docs/screenshots/settings-dns.png) | ![Client groups](docs/screenshots/client-groups.png) |

| Allowlist / Denylist | Pause blocking |
| --- | --- |
| ![Allowlist and denylist](docs/screenshots/allow-deny.png) | ![Pause blocking bar](docs/screenshots/pause-bar.png) |

| Blocked clients | Settings - Threat intelligence |
| --- | --- |
| ![Blocked clients editor](docs/screenshots/blocked-clients.png) | ![Threat intelligence settings](docs/screenshots/settings-threat-intel.png) |

| Enrich popup |
| --- |
| ![Enrichment result popup with lookup history and a block-host button](docs/screenshots/enrich-popup.png) |

## Why not just use AdGuard Home?

### What AdGuard Home actually is and how it works

AdGuard Home is a DNS sinkhole / filtering DNS proxy with a web UI, roughly:

1. You point your router or devices at it as their DNS server.
2. For every query it checks the domain against filter lists (hosts-file
   and AdBlock-syntax lists, refreshed from URLs you or AdGuard provide)
   and per-user allow/block rules.
3. Matches are answered locally (NXDOMAIN or `0.0.0.0`); everything else
   is forwarded to upstream resolvers, optionally over DNS-over-HTTPS/TLS/QUIC.
4. It also ships DHCP, parental control, "safe browsing", and query
   statistics/logging in the same binary, behind a web dashboard.

### Where the "data leak" concern comes from

None of this requires phoning home for the *core* ad-blocking function, but
several AdGuard Home features do talk to AdGuard's own infrastructure by
default, and that's the "leak" people mean:

- **Safe Browsing / Parental Control** send a (hashed, prefix-truncated)
  lookup for *every visited domain* to AdGuard's own cloud API
  (`family.adguard-dns.com` / AdGuard's safe-browsing endpoint) when those
  features are enabled - i.e. a copy of your browsing metadata leaves your
  network to a third party.
- **Update checks** ping AdGuard's servers on a schedule to check for new
  releases.
- The **default filter lists and default upstream DNS-over-HTTPS resolver**
  (AdGuard's own DoH server, `dns.adguard-dns.com`) route your DNS traffic
  and list refreshes through AdGuard-operated infrastructure unless you
  explicitly change them.
- It's closed telemetry-adjacent surface: even opt-in features are on by
  default in some builds, and a self-hosted tool whose job is "see every
  domain your network visits" is exactly the kind of software where any
  outbound call to a third party deserves scrutiny.

None of that makes AdGuard Home malicious - the vendor documents these
features - but for a tool that sees literally every domain every device on
your network resolves, "trust the vendor's cloud, by default" is a
reasonable thing to want to avoid.

### What DNS-shield does differently

DNS-shield implements the same core mechanism (DNS sinkhole + filter lists +
web UI) but keeps it **local-only by construction**:

- The only outbound network calls it ever makes are (a) to the blocklist
  URLs *you* configure, (b) to the upstream resolvers *you* configure, and
  (c) a threat-intel reputation lookup (VirusTotal/AbuseIPDB/AlienVault
  OTX) - gated by an API key *and* a separate "Enable public lookups"
  switch that's off by default, and even then only the instant you click
  "Enrich" on a specific domain/IP; see
  [Threat-intel enrichment](#threat-intel-enrichment-virustotal--abuseipdb--alienvault-otx--your-own)
  below, including the option to point Enrich at a reputation service you
  run yourself instead. There is no default AdGuard-operated endpoint,
  and nothing calls out on its own.
- No safe-browsing/parental-control cloud lookups, no update-check
  pings, no analytics, no telemetry of any kind.
- All state - config, cached blocklists, query stats/log, enrichment
  results - lives on your bind-mounted `./data` volume: a local SQLite
  database for config (`config.db`), one for the query log (`stats.db`),
  one for enrichment results (`enrichment.db`), plus cached list files.
  Nothing is sent anywhere else, and you can open any of these databases
  yourself with any SQLite client to verify exactly what's stored.
- Every setting is configurable from the dashboard - no editing a YAML
  file and restarting to change an upstream resolver or a blocklist.
- Small enough to actually read end to end; see [Architecture](#architecture)
  below for exactly what each file does.

This intentionally does **not** try to be a full AdGuard Home replacement -
no DHCP server, no DoH/DoT/DoQ termination, no parental control. It's the
"block ads/trackers network-wide from a Docker container, with nothing
leaving my network that I didn't ask for" subset.

## Quick start

```bash
git clone <this repo>
cd DNS-shield
docker compose up -d --build
```

On first start it seeds `./data/config.db` from `config/config.example.yaml`.
Open `http://<host>:3000`, log in with the default `admin` / `changeme`
credentials, **change the password** (Settings -> Web UI), and point a
device's DNS at `<host>:53` to test it.

To use it network-wide, set it as the DNS server in your router's DHCP
settings (or on individual devices).

The dashboard has three tabs (remembered across reloads): **Logs** - just
the query log browser; **Stats** - the summary cards, top blocked
domains, top queried domains overall, top querying clients, a query-type
breakdown, and a "blocked by" breakdown (which blocklist/rule is
responsible for the most blocks); and **Settings** - everything else
(DNS/web/logging settings, upstreams, blocklists, allow/deny lists,
client groups, the AdGuard Home importer, and "Delete all logged
queries" under Logging & blocklist refresh). The pause-blocking bar at
the top is always visible regardless of tab.

## Configuration

Every setting is editable from the dashboard's **Settings** section (DNS,
upstreams, web UI, logging, blocklists) and its dedicated pages (blocklists,
allow-list sources, allow/deny rules, client groups, log-ignore list) - no
file editing needed for day-to-day use.

Under the hood, the live config lives in `./data/config.db` (SQLite), and a
full copy is exported to `./data/config.backup.yaml` every 12 hours (and
once at every startup) purely as a human-readable backup/reference:

```yaml
dns:
  listen_address: "0.0.0.0"
  listen_port: 53
  upstreams: ["1.1.1.1:53", "9.9.9.9:53"]   # as many as you like - see below
  upstream_timeout_seconds: 3.0
  upstream_strategy: "in_order"  # or "fastest" / "most_stable" / "race" - see below
  upstream_stats_window_minutes: 15
  block_mode: "nxdomain"                     # or "null_ip"
  blocked_ipv4: "0.0.0.0"        # used when block_mode is "null_ip"
  blocked_ipv6: "::"              # ditto, for AAAA
  block_ipv6: false             # true: answer AAAA queries empty instead of forwarding
  block_non_latin: false        # true: block Cyrillic/Arabic/CJK/etc. domains - see below
  cache_enabled: true            # in-memory cache of upstream answers, per their own TTL
  cache_max_entries: 10000
  cache_min_ttl_seconds: 0        # floor applied to cached TTLs
  cache_max_ttl_seconds: 3600     # cap applied to cached TTLs
  resolve_client_names: false    # reverse-DNS client IPs for display (see below)
  client_name_resolver: ""       # e.g. "192.168.1.1:53" - your router, not an upstream
  client_name_cache_seconds: 3600

blocklists:
  refresh_interval_hours: 24
  sources:
    - name: "StevenBlack Unified Hosts"
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      enabled: true
  allow_sources: []   # same format, but overrides the blocklists - see below

allowlist: []   # always resolved normally, even if a blocklist matches
denylist: []    # always blocked, even if not on a blocklist
blocked_clients: []   # IPs/CIDRs with EVERY query blocked - see below

domain_upstreams: []   # route specific domains to specific resolvers - see below

client_groups: []   # per-IP/CIDR overrides, see below

web:
  listen_address: "0.0.0.0"
  listen_port: 3000
  username: "admin"
  password: "changeme"   # change this from the dashboard
  theme: "navy"           # 8 palettes, dark/light pairs - see Color themes below

logging:
  level: "INFO"             # Python log level; YAML-only, not in the dashboard
  retention_days: 30       # how long query log entries are kept in stats.db
  ignored_domains: []      # never logged, but still resolved/blocked normally
  ignored_clients: []      # same, by client IP/CIDR

enrichment:                    # threat-intel settings - see Threat-intel enrichment below
  public_enabled: false         # master switch for the 3 keys below - off by default
  virustotal_api_key: ""
  abuseipdb_api_key: ""
  otx_api_key: ""
  local_enabled: false           # your own reputation service - see below
  local_url: ""
  local_api_key: ""
```

This example file (`config/config.example.yaml`) only matters for a *fresh*
data volume's first boot, or to recover from a wiped `config.db` - see
[Editing the config file directly](#editing-the-config-file-directly) below.

### Encrypted upstream (DNS-over-TLS / DNS-over-HTTPS)

Any `upstreams` entry can be prefixed to encrypt the hop between
DNS-shield and that resolver, hiding query content from anything snooping
the path in between (e.g. your ISP) - the upstream operator itself can
still see what you ask it, same as with plain DNS:

```yaml
dns:
  upstreams:
    - "dot://1.1.1.1"                          # DNS-over-TLS
    - "doh://cloudflare-dns.com/dns-query"     # DNS-over-HTTPS
    - "https://dns.quad9.net/dns-query"        # DNS-over-HTTPS, full URL also works
```

Plain `host:port` entries use UDP with an automatic TCP retry if the reply
is truncated. DNS-shield itself still only ever listens for plain DNS from
your LAN clients on port 53 - there's no DoT/DoH/DoQ *listener*.

### Multiple upstreams and selection strategy

`dns.upstreams` takes as many resolvers as you want - all of them are
always available as fallback if earlier ones fail. `dns.upstream_strategy`
picks which one is tried *first* for each query - or, for `race`, all of
them at once:

- `in_order` (default) - try them in the order listed, top to bottom.
- `fastest` - try whichever has the lowest average response time over the
  last `upstream_stats_window_minutes` (15 by default).
- `most_stable` - try whichever has the fewest failures / most consistent
  response time in that window, favoring reliability over raw speed.
- `race` ("All at once - FIFO") - send the query to every configured
  upstream simultaneously and answer the client with whichever replies
  first; the rest keep running in the background purely so their
  latency/success still gets recorded, but their answer is discarded.
  Lowest possible latency at the cost of querying every upstream for
  every single request (more outbound traffic, and every upstream sees
  every query rather than just the one that "won").

A background thread health-checks every configured upstream every 2
minutes (regardless of which one traffic is actually using), so stats -
visible in the dashboard's Settings -> Upstream DNS servers table - stay
current even for a server the strategy has stopped picking, and it can be
picked again if it improves. This only ever probes the upstream hosts
already in your config.

A line starting with `#` in the Upstream DNS servers box is a comment and
is ignored - handy for keeping a resolver around (with a note on why)
without deleting and retyping it later.

### Upstream and blocklist hostnames are always resolvable and never logged

Whatever hostname a `dot://`/`doh://` upstream needs DNS to resolve (e.g.
`dns.nextdns.io`), or a blocklist/allow-list subscription URL's host (e.g.
`raw.githubusercontent.com`), is automatically exempt from every blocking
mechanism - above even a manual denylist entry and a pause-blocking
bypass wouldn't even need to check it - and left out of the query log by
default. No configuration needed: this is derived straight from
`dns.upstreams`, `domain_upstreams[].upstreams`, `client_groups[].upstreams`,
and every `blocklists.sources`/`blocklists.allow_sources` URL, every time
it's checked, so it stays correct whenever any of those change. The point
is to make it impossible to accidentally lock DNS-shield out of its own
upstream or its own blocklists (a coincidental blocklist match on either
hostname would otherwise be a self-inflicted outage - blocking your own
blocklist source is a particularly nasty one, since it would silently
stop all list refreshes), and to keep this constant background lookup out
of a log meant for what your devices are actually browsing to.

The three public threat-intel hosts (VirusTotal/AbuseIPDB/OTX - see
[Threat-intel enrichment](#threat-intel-enrichment-virustotal--abuseipdb--alienvault-otx--your-own)
below) get the same treatment, but **only once you've turned on
`enrichment.public_enabled`** - while that switch is off there is no
reason for DNS-shield to talk to them, so there's deliberately no
standing exemption for them either. Your own local enrichment endpoint's
host is exempted independently, whenever `enrichment.local_enabled` is on
and a URL is set.

### Per-domain and per-client DNS routing

`domain_upstreams` routes specific domains to specific resolvers,
regardless of which client asks - e.g. internal/corporate domains that
only your own DNS server knows about:

```yaml
domain_upstreams:
  - name: "Internal network"
    domains: ["corp.local", "internal.example"]
    upstreams: ["192.168.1.1:53"]
```

A `client_groups` entry can also carry its own `upstreams` list, used for
that client's queries instead of the global list (e.g. route a VPN
client's DNS through a different resolver). Precedence when multiple
could apply: a matching `domain_upstreams` rule wins first (domain routing
is usually a hard technical requirement), then a matched client group's
own `upstreams`, then the global `dns.upstreams`.

### Client hostnames (reverse DNS)

Set `dns.client_name_resolver` to your **router's** IP (not one of your
ad-filtering upstreams - your router is what actually knows DHCP client
names) and `dns.resolve_client_names: true`, and the dashboard's query log
and client list will show e.g. `laptop-jan.lan (192.168.1.50)` instead of
just the raw IP. Resolution happens in a background thread and is purely a
display aid - it never delays answering a client's actual query, and
nothing is written to disk (in-memory cache only, `dns.client_name_cache_seconds`).

### Per-client/group policies

`client_groups` lets you override the global policy for specific IPs or
CIDR ranges - e.g. a stricter denylist for kids' devices, or turning
filtering off entirely for a NAS/server that breaks when domains are
blocked. First matching group wins; a client that matches no group just
gets the global policy above:

```yaml
client_groups:
  - name: "Kids"
    match: ["192.168.1.50", "192.168.1.0/28"]
    enabled: true
    allowlist: []
    denylist: ["some-adult-site.example"]
  - name: "Guests"
    match: ["192.168.1.200/29"]
    enabled: false   # pass-through: no ad/tracker blocking for this group
```

Precedence for a query from a matched client: group denylist > global
denylist > group allowlist > global allowlist > group `enabled: false`
(no filtering at all) > the blocklists. Denylist beats allowlist at both
levels, so an explicit deny entry is truly "always blocked" even for a
domain that's also allowlisted (e.g. after a query-log Unblock, which
allowlists a domain - manually denylisting that same domain again still
works); allowlist only beats the *blocklists* (subscribed lists), which
is the main reason to allowlist something in the first place. Manage
groups (and their per-group allow/deny lists) from the dashboard or by
editing this list directly.

### Blocking a client entirely

`blocked_clients` is a separate, stronger mechanism from everything above:
an IP/CIDR here has *every* query blocked, for *every* domain - "no
communication with this host at all" rather than a domain-scoped rule. It
takes priority over `client_groups` and any per-domain allow/deny entry,
though a paused blocking window (see below) still bypasses it like
everything else.

The dashboard's **Block host** button does this for you - next to any
client IP wherever one's shown (the query log, the Stats tab's "Top
querying clients" table, and the [Enrich popup](#threat-intel-enrichment-virustotal--abuseipdb--alienvault-otx--your-own)
for an IP lookup) - and flips to **Unblock host** once that client is
blocked. Settings -> "Blocked clients" lists everything currently
blocked and lets you add or remove entries (including CIDR ranges) by
hand:

```yaml
blocked_clients:
  - "192.168.1.50"
  - "192.168.1.0/28"
```

### Disabling IPv6

If your network doesn't use IPv6, turn on `dns.block_ipv6` (dashboard:
Settings -> DNS -> "Disable IPv6"). AAAA queries then get an empty
`NOERROR` reply immediately - not NXDOMAIN, which would incorrectly tell a
dual-stack client the whole name doesn't exist - so clients fall back to
IPv4 right away instead of waiting out an IPv6 connection timeout first.
This skips the blocklist and upstream entirely for AAAA queries, and
they're not written to the query log either - with IPv6 disabled, every
device asks an AAAA query for everything, so logging them would just be
noise on every single lookup.

### Blocking non-Latin-script domains

`dns.block_non_latin` (dashboard: Settings -> DNS -> "Block non-Latin-script
domains") blocks domains that use Cyrillic, Arabic, CJK, Hangul, Greek,
Hebrew, Thai, Devanagari, or similar scripts, once their punycode/IDNA
labels are decoded back to Unicode. Plain ASCII and accented Latin domains
(`café.fr`, `münchen.de`) are never affected - only characters outside the
Latin script trigger it. The global/group allowlist always overrides this
if you need a specific exception. Off by default.

### DNS answer cache

`dns.cache_enabled` (on by default) keeps resolved answers in memory,
keyed by domain+record type, for as long as their own TTL says they're
valid - clamped between `cache_min_ttl_seconds` and `cache_max_ttl_seconds`
(handy if some upstream returns unusually short/long TTLs you don't
trust) and bounded to `cache_max_entries` with LRU eviction. A repeat
lookup for anything still cached is answered immediately, without
forwarding to an upstream at all - lower latency and less outbound query
volume for the CDN/ad/tracker hostnames that make up most repeat
traffic. Purely in-process memory: nothing is written to disk, and it's
empty again after a restart. The Stats tab shows current entry count and
hit rate; Settings -> DNS answer cache has a "Clear cache" button to
empty it on demand (e.g. right after changing upstreams, to stop
serving anything answered by the old one).

### Query log browser, quick-block, and quick-hide

The dashboard's **Query log** section searches the full retained history
(not just the last few entries) - filter by domain substring, client
(IP or resolved name) substring, record type, blocked/allowed, and a time
range, with pagination via "Load more". Each row has a **Block**/**Unblock**
button (whichever applies to that row's current state) and a **Hide**
button.

Block adds the domain to the global denylist; Unblock reverses whatever
caused that particular query to be blocked - removes a manual denylist
entry if that's why (denylist always wins over the allowlist - see
[Per-client/group policies](#per-clientgroup-policies) - so leaving a
stale denylist entry behind would otherwise silently defeat it), and also
adds the domain to the global allowlist, which overrides a blocklist-
source match. Hide adds the domain to `logging.ignored_domains` (see
below) - a shortcut for the same thing you can do from Settings, minus
the typing. Existing rows for that domain vanish from the currently
displayed page immediately for feedback, but only future queries actually
stop being logged - Hide doesn't delete anything already written to
`stats.db`, and doesn't affect resolution/blocking, only what shows up in
this log.

**Delete all logged queries** wipes every row from `stats.db` - a full
reset of the query log, not a filtered delete. Irreversible; the
dashboard asks for confirmation first.

A blocked row also shows an (i) icon - hover it to see exactly why that
query was blocked: which blocklist subscription matched (by name), a
manual denylist entry (global or a specific client group's), or the
non-Latin-script filter. This is computed at query time and stored per
row (a `reason` column on `stats.db`, backfilled as `null` for rows
logged before this existed - hover shows nothing for those).

Every domain and client address in the log also has a **Copy** button next
to it, for grabbing the exact value onto your clipboard (e.g. to paste into
a search, a firewall rule, or a ticket) without having to select the text
by hand. A client's address also gets a **Block host** button - see
[Blocking a client entirely](#blocking-a-client-entirely) above.

### Stats tab

Cards for total/blocked queries, block rate, blocklist domain count,
cache entries, and cache hit rate, plus five tables computed from the
full retained history in `stats.db` (not just what's currently on
screen elsewhere): **Top blocked domains**, **Top queried domains**
(everything, blocked and allowed - useful for spotting what a device
actually talks to), **Top querying clients** (busiest device on the
network), **Query types** (A/AAAA/CNAME/... breakdown), and **Blocked
by** (which specific blocklist subscription or rule is responsible for
the most blocks - the same reasons as the query log's (i) icon, just
aggregated). All of it updates live every 10 seconds alongside the rest
of the dashboard. Like the query log, the domain/client tables have a
**Copy** button on each row, and client rows also get a **Block host**
button.

### Threat-intel enrichment (VirusTotal / AbuseIPDB / AlienVault OTX / your own)

Every domain and IP address shown in the Query log and Stats tabs also has
an **Enrich** button, which looks up that indicator's reputation via
[VirusTotal](https://www.virustotal.com/), [AbuseIPDB](https://www.abuseipdb.com/),
[AlienVault OTX](https://otx.alienvault.com/), and/or a reputation service
of your own - configured in Settings -> Threat intelligence.

**This only ever runs when you click it.** There is no background
scanning, no automatic lookup of every query, no schedule, and no lookup
triggered by loading the dashboard or a DNS query resolving - clicking
Enrich is the only way an outbound call to any of these is ever made, and
only for the single indicator you clicked on.

The button itself is greyed out and unclickable, with a tooltip
explaining why, until at least one source is actually usable - so there's
nothing to accidentally click before you've set anything up.

**Public services (VirusTotal/AbuseIPDB/OTX)** need two things before
Enrich will call any of them: an API key (free-tier keys work fine), *and*
the **"Enable public lookups"** switch in Settings, which is **off by
default**. This is a deliberate second gate on top of the key - these
three are the one category of outbound call in this project that leaves
your own network, and DNS-shield exists specifically because another DNS
blocker made exactly that kind of call without asking (see
[Why not just use AdGuard Home?](#why-not-just-use-adguard-home) above) -
so saving a key alone never starts sending anything anywhere; you have to
flip the switch too. Configuring a key while the switch is off isn't
wasted, though: the popup still shows that source as "disabled" rather
than "not configured", so you can prepare it ahead of time and flip the
switch when you're ready. AbuseIPDB has no domain-lookup endpoint, so it's
skipped (not treated as an error) for domain targets and only ever
queried for IP targets; VirusTotal and OTX support both.

**Your own local service** has no such switch - it's not a third-party
call, it's infrastructure you run and pointed this at yourself. Turn on
**"Enable your own (local) reputation service"** and give it a URL (e.g.
something on your own LAN or a self-hosted tool); DNS-shield `POST`s
`{"target": "<domain-or-ip>", "type": "domain"|"ip"}` as JSON to that URL
(with `Authorization: Bearer <key>` if you set one) and expects back
`{"verdict": "safe"|"low"|"medium"|"high"|"critical", "score": 0-100,
"summary": "..."}` (`score`/`summary` optional) - a small enough contract
to put in front of anything: a script, an internal tool, even a different
open-source feed you already trust more. A response missing/mangling
`verdict` is treated as a failed lookup, not guessed at.

The result opens in a **new browser window**, with the background color
set by the worst verdict across every source that actually returned one -
a calm green for a clean/safe result, escalating through yellow and
orange to red for something flagged as malicious - along with each
source's own verdict and a short summary (engines flagging it, abuse
confidence score, pulse count, your local service's own summary, etc.). A
source that's unconfigured, disabled (public switch off), or failed (bad
key, rate limit, no data on record, unreachable, malformed response)
shows why instead of crashing the popup.

Every result - including unconfigured/disabled/failed ones - is recorded
locally in `data/enrichment.db`, purely so you have a record of past
lookups; nothing in that database is ever sent anywhere.

The popup also shows a **lookup history** table for that same target -
every past time you've clicked Enrich on it, newest first, with the
verdict and score it had *at that time* - so you can see whether an
indicator's reputation has moved since you last checked, without leaving
the popup. Only past results for the exact target you just looked up are
shown (`GET /api/enrich/history?target=...`), pulled straight from
`enrichment.db`; a first-time lookup just shows the one row for the
current result.

For an IP target - always a client that has queried DNS-shield, since
that's the only kind of IP the dashboard ever offers Enrich for - the
popup also has a **Block this host**/**Unblock this host** button, the
same feature as the query log/Stats "Block host" button, just reachable
without leaving the popup; see
[Blocking a client entirely](#blocking-a-client-entirely) above for what
it actually does.

### Pause blocking

The bar at the top of the dashboard can pause *all* blocking network-wide
for a chosen duration (10/30/60/120 seconds, 5/10/30/60 minutes, or until
you manually resume it) - useful for quickly checking whether DNS-shield
is the cause of something breaking, without having to hunt down and
temporarily remove a specific denylist entry or blocklist. While paused,
every query resolves as if no blocklist, denylist, or client group
existed; it self-expires exactly at the chosen time (no polling/cleanup
needed - the timestamp is just checked against the current time) or you
can hit "Resume blocking" early.

### Excluding domains/clients from the log

`logging.ignored_domains` / `logging.ignored_clients` (dashboard: Settings
-> Logging & blocklist refresh) keep specific domains or clients out of the
query log and stats entirely - they're still resolved and blocked exactly
as normal, this only controls what gets written to `stats.db`. Domain
entries also cover their subdomains; clients accept an exact IP or a CIDR
range.

### Color themes

Settings -> Web UI -> Color theme switches between eight palettes, four
dark and four light, paired by hue: Navy & Azure / Daylight & Azure,
Slate & Cyan / Mist & Cyan, Forest & Emerald / Meadow & Emerald, and
Plum & Violet / Lilac & Violet. Navy & Azure (dark) is the default.
Applies instantly, stored in `web.theme`.

### Editing the config file directly

DNS-shield's live configuration lives in `./data/config.db`, not a YAML
file - it's edited through the dashboard/REST API, and a full export is
written to `./data/config.backup.yaml` every 12 hours and at every startup
as a plain-text backup. That backup file is only ever *read* to seed a
fresh database (an empty data volume's first boot, or after you delete
`config.db` to reset). To hand-edit config as YAML: stop the container,
edit (or replace) `./data/config.backup.yaml`, delete `./data/config.db`
(and its `-wal`/`-shm` files, if present), and start it again.

## Importing from AdGuard Home

If you're migrating an existing AdGuard Home setup, both convert its
`AdGuardHome.yaml` the same way: filter and whitelist-filter subscriptions,
`user_rules` (both block rules and `@@` exceptions), upstream resolvers
(`tls://`/`https://` converted to `dot://`/`doh://`), listen address/port,
blocking mode, and each `clients.persistent[].ids` entry (IPs/CIDRs only -
MAC addresses aren't supported) as a `client_groups` entry.

**From the dashboard** (Settings -> "Import from AdGuard Home"): upload the
file, it's merged directly into the running config and takes effect
immediately - blocklists refresh right away. This **replaces** your current
blocklists and client groups with AdGuard's, but keeps everything else,
including your web login.

**From the command line**, for a fresh setup or to produce a file to review
before applying:

```bash
docker compose exec dns-shield python -m app.import_adguard /path/to/AdGuardHome.yaml
```

This only ever reads the two YAML files you point it at and writes one
output file - prints a summary of what was imported and, importantly, what
wasn't (parental control/safe browsing, DHCP, TLS termination, and your web
UI password - AdGuard stores a bcrypt hash that can't be turned back into
plaintext, so set that yourself from the dashboard). Full instructions for
applying the result are printed at the end of the run.

## Architecture

```
app/
  config.py          config storage: SQLite (data/config.db) as the live source of
                      truth, exported to data/config.backup.yaml every 12h
  netmatch.py         shared IP/CIDR matching for client groups and log-ignore rules
  blocklist.py        fetches + parses hosts/AdBlock-syntax lists (block and allow),
                       refreshes on a timer, caches lists to disk for offline restarts
  dns_server.py        dnslib-based UDP/TCP DNS server; blocks locally, serves cached
                        answers, or forwards the raw request packet to your upstreams
  dns_cache.py         in-memory, TTL-respecting cache of upstream answers (LRU-bounded,
                       nothing persisted to disk)
  upstream.py          upstream transports: plain UDP/TCP, DNS-over-TLS, DNS-over-HTTPS
  upstream_stats.py    rolling latency/success tracking + background health probing,
                       backing the fastest/most_stable upstream selection strategies
  client_names.py      background reverse-DNS (PTR) resolver for dashboard display only
  stats.py             query log storage: SQLite database (data/stats.db), async writes,
                       hourly pruning, filterable search for the query-log browser
  import_adguard.py    one-off AdGuard Home -> DNS-shield config converter (see above)
  enrichment.py         VirusTotal/AbuseIPDB/OTX reputation lookups - only ever called from
                        the "Enrich" button's endpoint, never on its own (see above)
  enrichment_store.py   local storage for enrichment results: SQLite (data/enrichment.db)
  web/server.py        FastAPI REST API + basic-auth, backing the dashboard
  web/static/          single self-contained dashboard page (no external assets/CDN)
  main.py              wires the above together and starts everything
```

Request flow: client -> DNS-shield (UDP/TCP :53) -> blocklist match? ->
NXDOMAIN/null-IP locally; otherwise cache hit? -> answer from the local
cache; otherwise forward the raw packet to an upstream resolver, relay the
raw reply back, and cache it for its remaining TTL. Every query is recorded
to the local stats log regardless of how it was answered.

### Concurrency

The DNS server handles each incoming query on its own thread (dnslib's
`ThreadingMixIn` UDP/TCP servers) - there's no fixed connection limit, and
since resolving is I/O-bound (waiting on the upstream socket, or on the
in-memory cache/blocklist lookup) this comfortably handles the query bursts
of a home or small-office network. It is not tuned for high sustained
throughput: each forwarded query opens a fresh UDP socket to the upstream
(no connection reuse/pooling), and thread-per-request has real overhead at
very high query rates. The cache above absorbs most of the repeat traffic
that would otherwise hit the upstream resolver.

## Security notes

- Change the default web UI password before exposing it beyond localhost.
- The web UI has no rate limiting; put it behind your own reverse proxy /
  VPN if you expose it outside your LAN.
- Port 53 needs root or `CAP_NET_BIND_SERVICE` in the container - the
  provided image runs as root for this (same approach as the official
  AdGuard Home / Pi-hole images). Run rootless via a compose override with
  `cap_add: [NET_BIND_SERVICE]` and a non-root `user:` if you need that.
- Threat-intel API keys (VirusTotal/AbuseIPDB/OTX/your own local service)
  are stored in `config.db`/`config.backup.yaml` like any other setting -
  anyone with access to the web UI or `./data` volume can read or use
  them. The Settings page and `GET /api/settings` never echo a key back,
  only whether one is set. `local_url` is stored and shown in plain text
  (it's a URL, not a secret) - don't put credentials in it, use the
  separate local API key field for that.
- `enrichment.public_enabled` (Settings -> Threat intelligence -> "Enable
  public lookups") is off by default and is the actual gate on whether
  VirusTotal/AbuseIPDB/OTX are ever contacted - saving a key for one of
  them does not turn this on by itself. Anyone with dashboard access can
  flip it, same as any other setting.

## Limitations / roadmap

- No DHCP server, no DoH/DoT/DoQ *listener* (only as an upstream transport -
  see above), no parental control / safe browsing.
- Client groups match by source IP/CIDR only, not MAC address or hostname.
- No built-in HTTPS for the web UI - put a reverse proxy in front of it if
  you need TLS.
- Blocklist matching is domain/subdomain based; it doesn't parse the full
  AdBlock rule grammar (element hiding, exceptions, regex rules).
