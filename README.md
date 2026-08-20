# DNS-shield

A small, self-hosted, network-wide DNS ad/tracker blocker you run in Docker.
It does the same core job as [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) -
sit as your network's DNS resolver and drop queries to ad/tracker domains -
but with a much smaller, auditable footprint and **no built-in calls to any
third-party cloud service**.

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
  URLs *you* list in `config.yaml`, and (b) to the upstream resolvers *you*
  list in `config.yaml`. There is no default AdGuard-operated endpoint.
- No safe-browsing/parental-control cloud lookups, no update-check
  pings, no analytics, no telemetry of any kind.
- All state - config, cached blocklists, query stats/log - lives on your
  bind-mounted `./data` volume: a local SQLite database for config
  (`config.db`) and one for the query log (`stats.db`), plus cached list
  files. Nothing is sent anywhere else, and you can open either database
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

The dashboard has two tabs (remembered across reloads): **Logs** - query
volume/block-rate stats, top blocked domains, and the query log browser -
and **Settings** - everything else (DNS/web/logging settings, upstreams,
blocklists, allow/deny lists, client groups, the AdGuard Home importer).
The pause-blocking bar at the top is always visible regardless of tab.

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
  upstream_strategy: "in_order"  # or "fastest" / "most_stable" - see below
  upstream_stats_window_minutes: 15
  block_mode: "nxdomain"                     # or "null_ip"
  block_ipv6: false             # true: answer AAAA queries empty instead of forwarding
  block_non_latin: false        # true: block Cyrillic/Arabic/CJK/etc. domains - see below
  cache_enabled: true            # in-memory cache of upstream answers, per their own TTL
  cache_max_entries: 10000
  cache_max_ttl_seconds: 3600
  resolve_client_names: false    # reverse-DNS client IPs for display (see below)
  client_name_resolver: ""       # e.g. "192.168.1.1:53" - your router, not an upstream

blocklists:
  refresh_interval_hours: 24
  sources:
    - name: "StevenBlack Unified Hosts"
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      enabled: true
  allow_sources: []   # same format, but overrides the blocklists - see below

allowlist: []   # always resolved normally, even if a blocklist matches
denylist: []    # always blocked, even if not on a blocklist

domain_upstreams: []   # route specific domains to specific resolvers - see below

client_groups: []   # per-IP/CIDR overrides, see below

web:
  listen_port: 3000
  username: "admin"
  password: "changeme"   # change this from the dashboard
  theme: "navy"           # "navy", "slate", "forest", or "plum"

logging:
  retention_days: 30       # how long query log entries are kept in stats.db
  ignored_domains: []      # never logged, but still resolved/blocked normally
  ignored_clients: []      # same, by client IP/CIDR
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
picks which one is tried *first* for each query:

- `in_order` (default) - try them in the order listed, top to bottom.
- `fastest` - try whichever has the lowest average response time over the
  last `upstream_stats_window_minutes` (15 by default).
- `most_stable` - try whichever has the fewest failures / most consistent
  response time in that window, favoring reliability over raw speed.

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

A blocked row also shows an (i) icon - hover it to see exactly why that
query was blocked: which blocklist subscription matched (by name), a
manual denylist entry (global or a specific client group's), or the
non-Latin-script filter. This is computed at query time and stored per
row (a `reason` column on `stats.db`, backfilled as `null` for rows
logged before this existed - hover shows nothing for those).

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

## Limitations / roadmap

- No DHCP server, no DoH/DoT/DoQ *listener* (only as an upstream transport -
  see above), no parental control / safe browsing.
- Client groups match by source IP/CIDR only, not MAC address or hostname.
- No built-in HTTPS for the web UI - put a reverse proxy in front of it if
  you need TLS.
- Blocklist matching is domain/subdomain based; it doesn't parse the full
  AdBlock rule grammar (element hiding, exceptions, regex rules).
