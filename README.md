# DNS-shield

<p align="center"><img src="docs/logo.png" alt="DNS-shield logo" width="160"></p>

*Czytasz to po polsku? Zobacz [`README.PL.md`](README.PL.md).*

A small, self-hosted, network-wide DNS ad/tracker blocker you run in Docker.
It does the same core job as [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) -
sit as your network's DNS resolver and drop queries to ad/tracker domains -
but with a much smaller, auditable footprint and **no built-in calls to any
third-party cloud service**.

See [`docs/features.html`](docs/features.html) for a categorized map of
every feature this ships with (open it in a browser after cloning, or
download it directly from GitHub).

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

| Settings - Notifications (email, webhooks, browser, URL ping) | Enrich popup |
| --- | --- |
| ![Notification settings including the URL ping section](docs/screenshots/settings-notifications.png) | ![Enrichment result popup with lookup history and a block-host button](docs/screenshots/enrich-popup.png) |

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
  URLs *you* configure, (b) to the upstream resolvers *you* configure,
  (c) a threat-intel reputation lookup (VirusTotal/AbuseIPDB/AlienVault
  OTX) - gated by an API key *and* a separate "Enable public lookups"
  switch that's off by default, and even then only the instant you click
  "Enrich" on a specific domain/IP; see
  [Threat-intel enrichment](#threat-intel-enrichment-virustotal--abuseipdb--alienvault-otx--your-own)
  below, including the option to point Enrich at a reputation service you
  run yourself instead - and (d) an email to the SMTP server *you*
  configure, off by default, only when [anomaly detection](#local-anomaly-detection)
  is on and finds something; see [Notifications](#notifications) below.
  There is no default AdGuard-operated endpoint, and nothing calls out on
  its own.
- No safe-browsing/parental-control cloud lookups, no update-check
  pings, no analytics, no telemetry of any kind.
- All state - config, cached blocklists, query stats/log, enrichment
  results, detected anomalies - lives on your bind-mounted `./data`
  volume: a local SQLite database for config (`config.db`), one for the
  query log (`stats.db`), one for enrichment results (`enrichment.db`),
  one for [anomaly detection](#local-anomaly-detection) alerts
  (`anomalies.db`), plus cached list files. Nothing is sent anywhere
  else, and you can open any of these databases yourself with any
  SQLite client to verify exactly what's stored.
- Every setting is configurable from the dashboard - no editing a YAML
  file and restarting to change an upstream resolver or a blocklist.
- Small enough to actually read end to end; see [Architecture](#architecture)
  below for exactly what each file does.

This intentionally does **not** try to be a full AdGuard Home replacement -
no DHCP server, no DoQ, no per-app controls. It's the "block ads/trackers
network-wide from a Docker container, with nothing leaving my network
that I didn't ask for" subset, plus the DNS-level pieces of parental
control that fit that subset cleanly: forced SafeSearch/Restricted Mode
and category blocklists scoped to a client group (see
[Parental control / SafeSearch](#parental-control--safesearch)).

## Quick start

```bash
git clone <this repo>
cd DNS-shield
docker compose up -d --build
```

On first start it seeds `./data/config.db` from `config/config.example.yaml`.
Open `https://<host>:3000` and you'll land on a public, read-only view
(query trend + top blocked domains, no sign-in needed) with a "Sign in"
link. HTTPS is on by default with a self-signed certificate DNS-shield
generates for itself on first boot - your browser will show a "not
secure"/"not trusted" warning the first time you connect, since nothing
vouches for a self-signed certificate; click through it once (see
[HTTPS for the dashboard](#https-for-the-dashboard) below for the
actually-correct fix, and for how to opt back into plain HTTP if you'd
rather not deal with that warning on a LAN-only deployment). Log in with
the default `admin` / `changeme` credentials, **change the password**
(Settings -> General -> "Your account"), and point a device's DNS at
`<host>:53` to test it.

To use it network-wide, set it as the DNS server in your router's DHCP
settings (or on individual devices).

Once signed in, the dashboard has four tabs (remembered across reloads):
**Logs** - the query log browser; **Anomalies** - anything the local
anomaly detector or your alert rules have flagged; **Stats** - the
summary cards, top blocked domains, top queried domains overall, top
querying clients, a query-type breakdown, and a "blocked by" breakdown
(which blocklist/rule is responsible for the most blocks); and
**Settings** - everything else (DNS/web settings, user accounts,
upstreams, blocklists, allow/deny lists, client groups, the AdGuard Home
importer, and "Delete all logged queries" under Logging & blocklist
refresh). The pause-blocking bar at the top is visible to Administrator
accounts only - see **Multi-user accounts, roles, and the public view**
below.

## Networking: host mode by default

The shipped `docker-compose.yml` runs the container with
`network_mode: host` rather than the usual bridge network + `ports:`
list. This isn't just for DHCP (see below) - **it's what lets DNS-shield
see each device's real IP address at all.** With bridge networking and
published ports, Docker forwards traffic to the container through NAT
(and, for UDP in particular, its own userland proxy), which replaces
every client's real source address with Docker's own gateway address
(typically `172.17.0.1`) before your query ever reaches the resolver.
Since almost every feature here is keyed on the querying client's IP -
client groups, per-client stats, blocked-clients rules, anomaly
detection, alert rules, DHCP, rogue-DHCP detection, and the
[client-domain graph](#client-domain-graph) - bridge mode
silently breaks all of them at once: every device on your network looks
like the same one "client" to DNS-shield. Host networking removes Docker's
NAT entirely, so `handler.client_address` (and anything built on it) is
the genuine LAN IP.

The trade-off: with `network_mode: host` there's no `ports:` list to
edit (Docker ignores it in this mode) - the container binds directly to
whatever ports its own config asks for on the host: `53` for DNS, `3000`
for the dashboard, plus `80`/`443` if you turn on the
[reverse proxy](#reverse-proxy-optional), `853` for DNS-over-TLS, or `67`
for DHCP, each only when its own feature is actually enabled. Make sure
nothing else on the host is already bound to a port you plan to use -
most commonly `53`: many Linux distributions run `systemd-resolved`'s
own stub listener on `127.0.0.1:53` by default, which doesn't conflict,
but a full local resolver bound to `0.0.0.0:53` would (`sudo ss -ulpn
'sport = :53'` to check).

If you'd rather keep the container network-isolated and don't need
per-client accuracy (for example, DNS-shield is the last hop behind
another resolver/forwarder that already collapses every query to one
source anyway), you can still switch back to bridge networking:

```yaml
services:
  dns-shield:
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "3000:3000/tcp"
```

(add `80:80/tcp` and `443:443/tcp` too if you're using the reverse
proxy, and `853:853/tcp` for DNS-over-TLS). Just be aware every client
will then show up as Docker's gateway address, `mac:` matching in
[client groups](#per-clientgroup-policies) won't see your
LAN's real ARP table, and DHCP won't work at all (see
[DHCP server](#dhcp-server-optional) below).

## Configuration

Every setting is editable from the dashboard's **Settings** section - no
file editing needed for day-to-day use. Settings is split into its own
sub-tabs by topic: **General** (web UI, config backup), **DNS** (core resolver, upstream
servers, per-domain routing, custom records), **Logging** (retention,
excluded domains/clients), **Threat intelligence**, **Import** (AdGuard
Home / Pi-hole), **Blocklists** (sources, suggested lists, allow-list
sources, refresh schedule), **Own lists** (allowlist, denylist, regex
denylist), **Clients** (blocked clients, client groups), and **Cleans**
(DNS answer cache, delete all logged queries).

Under the hood, the live config lives in `./data/config.db` (SQLite), and a
full copy is exported to `./data/config.backup.yaml` every 12 hours (and
once at every startup) purely as a human-readable backup/reference:

```yaml
dns:
  listen_address: "0.0.0.0"
  listen_port: 53
  upstreams: ["1.1.1.1:53", "9.9.9.9:53"]   # as many as you like - see below
  upstream_timeout_seconds: 3.0
  upstream_strategy: "in_order"  # or "fastest" / "most_stable" / "race" / "random" - see below
  upstream_stats_window_minutes: 15
  block_mode: "nxdomain"                     # or "null_ip"
  blocked_ipv4: "0.0.0.0"        # used when block_mode is "null_ip"
  blocked_ipv6: "::"              # ditto, for AAAA
  block_page_enabled: false      # serve a local "blocked" page - see below
  block_page_port: 80
  block_ipv6: false             # true: answer AAAA queries empty instead of forwarding
  block_non_latin: false        # true: block Cyrillic/Arabic/CJK/etc. domains - see below
  regex_denylist_enabled: false  # experimental - see Regex denylist below
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
denylist_regex: []   # experimental regex denylist, see below - off unless regex_denylist_enabled
blocked_clients: []   # IPs/CIDRs with EVERY query blocked - see below

dns_rewrites: []   # custom local A/AAAA records - see below

domain_upstreams: []   # route specific domains to specific resolvers - see below

client_groups: []   # per-IP/CIDR overrides, see below

web:
  listen_address: "0.0.0.0"
  listen_port: 3000
  theme: "navy"           # 8 palettes, dark/light pairs - see Color themes below

# Dashboard accounts - see "Multi-user accounts, roles, and the public
# view" below. On first start (or upgrading from a version that only had
# web.username/web.password above), a single admin account is created
# here automatically, with the password converted to a bcrypt hash.
# users: []

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
[Resetting config from a hand-edited YAML file](#resetting-config-from-a-hand-edited-yaml-file) below.

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
is truncated. This section is only about the *upstream* hop - DNS-shield
also always listens for plain DNS from your LAN clients on port 53, plus
optionally DoH/DoT for clients that want an encrypted hop to DNS-shield
itself; see [DNS-over-HTTPS / DNS-over-TLS for clients](#dns-over-https--dns-over-tls-for-clients)
below.

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
- `random` - shuffle the list and try it in that random order for each
  query, spreading load across providers instead of always favoring one.
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

### Disabling an upstream without removing it

Each configured upstream has its own Disable/Enable button in the
dashboard's Settings -> Upstream DNS servers table - it stays in your list
(and in the health-stats table) but is skipped when actually resolving
queries, so you don't lose the address or its config-file/import history
by deleting it outright. Under the hood this just prefixes the entry with
`#` in `dns.upstreams` (or `domain_upstreams[].upstreams` /
`client_groups[].upstreams`, if you disable one there) - the same
convention as commenting a line out by hand in the "one per line" textarea
above the table, or in a hand-edited config file.

### DNSSEC

`dns.dnssec_enabled` (Settings -> DNS, off by default) makes DNS-shield
set the DNSSEC OK (`DO`) bit on every query it forwards and check the
`AD` (Authenticated Data) flag on the reply. This is **trust-in-upstream**
DNSSEC handling, not independent cryptographic validation: DNS-shield
doesn't parse RRSIG/DNSKEY/DS records or walk the chain of trust itself
(that's a large amount of crypto machinery this project isn't taking on),
it relies on the upstream resolver having already validated and asks it
to say so. Point it at a validating public resolver (1.1.1.1, 9.9.9.9, and
8.8.8.8 all validate by default) for this to mean anything - an upstream
that doesn't validate will simply never set `AD`, and this feature has
nothing to check.

Because checking a domain's status shouldn't mean redoing verification on
every single query for it, results are kept in a small in-memory cache
independent of the regular DNS answer cache - `{domain: (secure, expires
at)}` - with its own TTL, `dns.dnssec_cache_seconds` (default 3600). This
matters because a query answered from the *regular* answer cache never
reaches the forwarding code path at all, so without a separate cache
DNS-shield would have no idea whether a cached answer was ever
DNSSEC-authenticated; the dedicated cache is populated only on a live
upstream round-trip and is what `GET /api/status`'s `dnssec.cached_domains`
counts (`secure`/`insecure`) are read from. This is observability, not
enforcement - an insecure/unsigned result is normal for the large fraction
of domains that don't sign their zone at all, so DNS-shield doesn't block
or otherwise treat unsigned answers differently; a validating upstream
already refuses (SERVFAIL) to hand back an answer whose signature fails
verification on its own, before DNS-shield ever sees it.

Turning the setting back off (or leaving it off) reverts to exactly the
pre-existing behavior - queries are packed and forwarded with no EDNS0
record added, at no extra cost.

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

### Custom DNS records ("rewrites")

`dns_rewrites` answers a hostname with an IP you choose, entirely locally -
no upstream query, no blocklist involvement. Handy for internal hostnames
your public DNS has no idea about:

```yaml
dns_rewrites:
  - name: "nas.home"
    type: "A"
    value: "192.168.1.10"
```

A plain rewrite name (no `*`/`?`) matches the name and its subdomains (so
`printer.nas.home` also resolves, from the entry above); a name containing
`*` (any run of characters) or `?` (any single character) is matched as a
glob pattern against the full queried name instead, so you can be more
precise about what it covers:

```yaml
dns_rewrites:
  - name: "*.internal.example"
    type: "A"
    value: "10.0.0.5"
```

`*.internal.example` matches `vpn.internal.example` and
`db.staging.internal.example`, but - unlike the plain-name form above -
*not* `internal.example` itself, since the pattern requires at least one
character before the literal `.internal.example`; add a second entry for
the bare domain if you want that too. `type` can be `A`, `AAAA`, `CNAME`,
or `TXT`; a `CNAME` rewrite's target is returned as-is, never itself
resolved or chased further, to keep this a flat lookup that always
terminates. It's checked
*after* blocking, not before: a fully blocked client or an already-blocked
domain still behaves as blocked regardless of any rewrite - a rewrite is
an answer, not an exemption. Manage rewrites from the dashboard
(Settings -> Custom DNS records) or by editing the list directly.

### Blocklist formats and suggested lists

Blocklist sources come in three common formats, and lists in the wild
aren't all the same one - some even mix them within a single file:

- **hosts file syntax**: `0.0.0.0 ads.example.com`
- **AdBlock/uBlock syntax**: `||ads.example.com^`
- **plain domain list**: `ads.example.com`

DNS-shield auto-detects the format of every line as it fetches a source,
so you can point it at any of the three (or a source that mixes them)
without picking one yourself. The dashboard's Blocklists table shows the
detected format under each source's domain count - e.g. "hosts file
(0.0.0.0/127.0.0.1 domain)", or "mixed formats (...)" for a source that
genuinely combines more than one syntax (a stray line or two doesn't
count - only a real mix is reported that way).

AdBlock/uBlock sources can also carry `@@||domain^` exception lines - many
popular lists use them to carve out a subdomain from a broader rule
earlier in the same file. DNS-shield honors those: a domain matched by a
source's own exception rule is treated the same as if you'd allowlisted
it yourself, so it's never blocked by that source. For a client group's
own extra `blocklist_sources`, an exception only exempts that group, the
same way the group's blocking is additive-only (see below). See
[Limitations](#limitations--roadmap) for what's deliberately *not*
interpreted from the AdBlock grammar, and why.

The Blocklists section also has a **Suggested lists** table: a short,
fixed list baked into DNS-shield itself (nothing fetched to build it) -
StevenBlack's Unified Hosts, AdGuard's own DNS filter, a handful of
[Firebog](https://firebog.net)'s recommended ("ticked") lists,
[HaGeZi's](https://github.com/hagezi/dns-blocklists) actively maintained
Multi PRO, Threat Intelligence Feeds, and Newly Registered Domains lists
(see below), badmojr's [1Hosts (Lite)](https://github.com/badmojr/1Hosts),
and DurableNapkin's scam-focused list. Clicking Add just fills in the
normal add-a-source form for you; the list is then fetched, and from
there can be disabled or removed exactly like any source you'd typed in
by hand. An entry drops off Suggested lists once you've added it - there's
nothing left to suggest - so the list only ever shows what you haven't
already picked up. The same catalog is also offered per client group, in
the Clients tab (see [Parental control](#parental-control--safesearch)
above).

Adding a source anywhere in the dashboard - here, Allow sources, a client
group's own extra lists, or a watch list under Alert rules - fetches and
re-parses *every* configured list before responding, not just the new
one, so it can take a few seconds on a slow connection or with a lot of
lists already added. The Add button shows a spinner and stays disabled
for that wait, and a small toast confirms once it's done - both replace
what used to be a silent pause with no indication anything was happening.

All of a category's sources (blocklists, allow sources, a group's own
lists, etc.) are fetched concurrently, not one at a time, so adding one
more list to an already-long chain doesn't multiply the wait. On startup
specifically, DNS-shield first loads whatever was cached on disk from
the last successful fetch - effectively instant, so blocking is already
active before the dashboard or DNS server even finish coming up - then
fetches everything live in the background a moment later. Only a
genuinely first-ever run, with nothing cached yet anywhere, waits on the
network before it's protected.

A URL you add here (or under Allow sources, a client group's own extra
lists, or Alert rules' own watch lists) is resolved and checked before
DNS-shield ever fetches it: a hostname resolving to a private, loopback,
link-local, or otherwise non-public address is rejected with an error
instead of being fetched, so an admin account can't be used to make the
server issue a request into your own LAN or at `127.0.0.1` (SSRF) by
pointing a "public blocklist" field at an internal address. This check is
scoped to subscription-style URL fields specifically - it does not apply
to `enrichment.local_url`, ping-check URLs, or notification webhook URLs,
which are meant to be able to target your own internal services.

That upfront check alone would still leave a narrow
[DNS-rebinding](https://en.wikipedia.org/wiki/DNS_rebinding)-style gap: a
malicious DNS server could answer the validation lookup with a public
address and the fetch's own, separate lookup moments later with a private
one. The actual fetch is guarded against this too - the private-address
check is re-applied at the exact moment the connection is opened, using
the hostname's real resolution for that specific request, not just the
upfront one - so a source can't pass validation with one address and then
connect to a different, private one underneath it.

### Newly registered domains (NRD)

Enterprise DNS security products (Infoblox's BloxOne Threat Defense calls
this "Newly Observed Domains", and it's a standard feature of Cisco
Umbrella and similar) block or flag any domain registered within roughly
the last 7-30 days, on the observation that phishing and malware campaigns
overwhelmingly register a domain and put it to use within days - by the
time a domain's been live a month, it's already made it past the window
where this technique catches anything. It's a real, effective technique
that doesn't need machine learning or a live feed subscription to
implement - it's just another domain list, so it plugs into the exact
same `blocklists.sources`/`blocklist_sources` mechanism as everything
else in this section. The Suggested lists catalog includes **HaGeZi
Newly Registered Domains (7-day)** for exactly this.

Read this before turning it on, though - it's a real tradeoff, not a free
win:

- **It's enormous.** ~2.8 million domains get registered somewhere in the
  world on a given day, and the list is refreshed daily. Loaded, it costs
  roughly **650MB of RAM** (measured directly - see
  [Concurrency](#concurrency) for how blocklists are held fully in memory
  as `frozenset`s for O(1) matching, and what that costs in general). On
  a resource-constrained host, that alone may be a reason to skip it -
  and if you run multiple [DNS workers](#concurrency), each one loads its
  own independent copy.
- **It blocks legitimate new sites too.** A brand-new SaaS product, a
  friend's personal blog, a startup that just launched - all indistinguishable
  from a phishing domain by registration date alone, and all blocked for
  their first week. This is the accepted cost of the technique in every
  product that ships it, not a bug in this implementation.

Given both, consider adding it as a specific client group's own extra
`blocklist_sources` entry (a security-conscious admin's own devices,
say) rather than the global list, so the false-positive cost lands only
where you've chosen to accept it - the same reasoning as the parental-control
category lists above. Only the 7-day window is offered; HaGeZi also
publishes 14/21/28/35-day-old windows at
[github.com/hagezi/nrd](https://github.com/hagezi/nrd) if you want to add
one by hand, but the marginal security value drops sharply with domain
age while the memory cost stays just as large, so they aren't suggested
here.

DNS-shield's [local anomaly detection](#local-anomaly-detection) already
covers an adjacent enterprise technique - the `domain_burst` heuristic's
entropy scoring flags a client rapidly querying many high-entropy,
algorithmically-generated-looking domains, the same DGA (Domain Generation
Algorithm) pattern BloxOne's ML-based analytics are built to catch for
malware command-and-control traffic - so that piece already exists
independent of any list subscription.

### Regex denylist (experimental)

`denylist_regex` blocks any query name matching a regular expression,
checked against the full name - e.g. `^ads?[0-9]*\.` catches
`ad.`/`ad1.`/`ads2.`-style subdomains across every domain at once,
something a plain domain/subdomain denylist entry can't express. It's off
by default (`dns.regex_denylist_enabled`) and marked experimental in the
dashboard for a reason: every enabled pattern is checked against **every
single query**, so the per-query CPU cost grows with how many patterns you
have. Patterns are compiled once and cached in memory - never recompiled
per query - but the matching itself is still real work, so this is meant
for a handful of hand-picked rules, not a full list. An invalid pattern is
rejected with an error when you try to add it, rather than silently
skipped later. Manage it from the dashboard (Settings -> Regex denylist)
or by editing `denylist_regex` directly.

A pattern crafted for [catastrophic
backtracking](https://en.wikipedia.org/wiki/ReDoS) (e.g. `(a+)+$`) is
rejected outright when you try to add it - a handful of adversarial probe
strings are matched against it first, and a pattern that takes too long
against any of them never makes it into `denylist_regex` at all. This
applies whether the pattern comes from the dashboard, the API, or a
Pi-hole import's own regex-deny rules. Matching itself is also
time-boxed per query (using the third-party `regex` engine instead of
Python's built-in `re`, which has no way to bound match time) - a pattern
that somehow still runs too long against one specific query name just
fails open for that single query (logged, treated as no match) instead of
blocking the resolver or the dashboard for everyone. Without this, a
single crafted ~30-character query name could stall DNS resolution and
the web UI for well over a minute.

### Client hostnames (reverse DNS)

Set `dns.client_name_resolver` to your **router's** IP (not one of your
ad-filtering upstreams - your router is what actually knows DHCP client
names) and `dns.resolve_client_names: true`, and the dashboard's query log
and client list will show e.g. `laptop-jan.lan (192.168.1.50)` instead of
just the raw IP. Resolution happens in a background thread and is purely a
display aid - it never delays answering a client's actual query, and
nothing is written to disk (in-memory cache only, `dns.client_name_cache_seconds`).

### Per-client/group policies

`client_groups` lets you override the global policy for specific clients -
e.g. a stricter denylist for kids' devices, or turning filtering off
entirely for a NAS/server that breaks when domains are blocked. A client
that matches no group just gets the global policy above; when several
groups match, the most specific one wins (see
[Priorities](#priorities-default-group-individual-host) below). A `match` entry can be an IP/CIDR (the default), a MAC
address as `mac:AA:BB:CC:DD:EE:FF`, or a resolved hostname as
`host:name` (or `host:*.suffix` for a suffix match):

```yaml
client_groups:
  - name: "Kids"
    match: ["192.168.1.50", "192.168.1.0/28"]
    enabled: true
    allowlist: []
    denylist: ["some-adult-site.example"]
    blocklist_sources:
      - name: "Extra kids-safe list"
        url: "https://example.org/extra-blocklist.txt"
        enabled: true
  - name: "Guests"
    match: ["192.168.1.200/29"]
    enabled: false   # pass-through: no ad/tracker blocking for this group
  - name: "Phones"
    match: ["mac:AA:BB:CC:DD:EE:FF", "host:kids-tablet"]
    enabled: true
```

#### Priorities: default, group, individual host

Settings apply in three layers, and the more specific layer wins:
**default** (the global policy) < **group / address pool** (a range such
as `192.168.1.0/24` or `10.0.0.0/8`) < **individual host** (one IP, a
`mac:` or an exact `host:` name). The order of groups in the list does not
matter. When more than one group matches a client, the winner is chosen by
its most specific matching pattern:

1. a single IP (including `/32` and `/128`)
2. `mac:`
3. `host:name`
4. `host:*.suffix` (a longer suffix beats a shorter one)
5. an address range - a longer prefix beats a shorter one (`/28` > `/24` >
   `/16` > `/8`; the same for IPv6)

Equally specific groups fall back to list order. The winning group's
settings are used as they are - an individual host does **not** inherit
its pool's allow/deny lists, upstreams, SafeSearch or schedule, so give the
host group everything it needs. Example: put a whole subnet under strict
filtering but let one trusted machine bypass it:

```yaml
client_groups:
  - name: "Kids network"
    match: ["192.168.10.0/24"]
    enabled: true
    denylist: ["games.example"]
  - name: "Dad's laptop"
    match: ["192.168.10.5"]
    enabled: false
```

The same rule decides a client's upstream override, SafeSearch, bedtime
schedule, extra blocklists and the group shown in the query log.

`mac:` matching reads the kernel's ARP table (`/proc/net/arp`) - it only
contains entries for devices DNS-shield's host has actually talked to at
the link layer, and it's only populated with real LAN entries when the
container shares the host's network (`network_mode: host` in
`docker-compose.yml`, which is the shipped default - see
[Networking: host mode by default](#networking-host-mode-by-default) -
or a macvlan setup); if you've switched to bridge networking instead, it
only sees its own bridge, so `mac:` patterns won't match anything there.
`host:` matching uses the same
resolved-hostname cache as `dns.resolve_client_names` above and requires
that setting to be on - a client's hostname is only known once resolution
has completed for it at least once, so the very first query from a new
client can't match a `host:` pattern.

Precedence for a query from a matched client: group denylist > global
denylist > group allowlist > global allowlist > group `enabled: false`
(no filtering at all) > the blocklists > the group's own extra
`blocklist_sources`. Denylist beats allowlist at both levels, so an
explicit deny entry is truly "always blocked" even for a domain that's
also allowlisted (e.g. after a query-log Unblock, which allowlists a
domain - manually denylisting that same domain again still works);
allowlist only beats the *blocklists* (subscribed lists), which is the
main reason to allowlist something in the first place. Manage groups
(and their per-group allow/deny lists) from the dashboard or by editing
this list directly.

In the dashboard (Settings > Clients) each group card has a **Filtering
for this group** switch - on means the blocklists and rules apply, off
means pass-through (`enabled: false`) - and a **Clients in this group**
editor: type one or several entries (IP, CIDR, `mac:...`, `host:...`,
separated by commas or spaces) and press Add, or click the x on a chip to
remove one. **Rename** next to the group's name changes it in place:
users' *allowed client groups* that referenced the old name follow the
rename and the group's extra blocklists keep working, and names must be
unique (case-insensitive, up to 255 characters). Entries are validated and normalized (MACs upper-cased with
colons, hostnames lower-cased, duplicates dropped) when a group is created
or extended, and a group can't lose its last entry (delete the group
instead). The same actions are available over the API:
`POST /api/client-groups/{index}/match` with `{"patterns": [...]}`,
`DELETE /api/client-groups/{index}/match?pattern=...` and
`PUT /api/client-groups/{index}/enabled` with `{"enabled": true|false}`
and `PUT /api/client-groups/{index}/name` with `{"name": "..."}`.

A group's `blocklist_sources` are its own subscribed lists (same
hosts/AdBlock/plain formats and fetch/parse/cache behavior as the global
Blocklists section), fetched and matched *in addition to* the global
blocklist for clients in that group - never a replacement. This is
one-directional by design: a group can only end up *stricter* than the
default (e.g. an extra adult-content list on top of the usual ad/tracker
lists for a kids' devices group). Wanting a *lighter* list for a group is
already covered by the existing per-group allowlist and the `enabled:
false` pass-through toggle above. Manage a group's extra sources from its
card in the dashboard's Clients tab, right below its allow/deny lists.

### Parental control / SafeSearch

Two DNS-level mechanisms cover the parental-control ground a DNS resolver
can actually reach - both are opt-in, and both build on `client_groups`
above rather than adding a separate subsystem:

- **Forced SafeSearch / Restricted Mode**: `dns.safe_search_enabled: true`
  (Settings -> DNS) rewrites the actual A/AAAA answer for Google, Bing,
  DuckDuckGo, YouTube, and Yandex's own search/video hostnames to each
  provider's documented safe-mode enforcement hostname (e.g.
  `forcesafesearch.google.com`, `restrict.youtube.com`), resolved live
  through your configured upstreams and cached exactly like any other
  answer. Only the specific search/video hostnames are touched (`google.
  <tld>`, `www.google.<tld>`, `youtube.com`, `bing.com`, `duckduckgo.com`,
  `yandex.ru`/`.com`, and a few equivalents) - other subdomains of the
  same domain (`mail.google.com`, `accounts.google.com`, `drive.google.com`)
  resolve normally, so this doesn't touch anything but the search/video
  surface itself. A client group can override the global setting with its
  own "SafeSearch override" (Clients tab, on each group's card): always
  on, always off, or inherit the global setting - the usual way to force
  it on for a kids' devices group regardless of the network-wide default.
- **Category blocklists via client groups**: the existing per-group
  `blocklist_sources` mechanism (above) is also how you add adult-content,
  gambling, or social-media blocking for specific clients only. The
  dashboard's Suggested lists picker on each group's card includes a
  "Parental control" category - HaGeZi's actively maintained NSFW,
  Gambling, Social Networks, Anti-Piracy, and Fake/Scam-Sites lists -
  alongside the same picker on the global Blocklists tab if you want one
  of them applied network-wide instead.

Neither mechanism can see inside HTTPS traffic or inspect page content -
this is DNS-level control (which hostname resolves to what), not a content
filter or a supervised-browsing product. A technically capable teenager
who changes their device's DNS server or uses a VPN bypasses all of it,
same as with any DNS-based parental control (AdGuard Home and Pi-hole
included) - pair it with your router blocking outbound DNS-over-HTTPS/TLS
to third parties and forcing all LAN DNS through DNS-shield if you need
that to actually hold.

A third piece, also opt-in per group: a **bedtime schedule** that blocks
every query from a group's clients during one or more time windows -
"no internet 22:00-07:00" rather than "no adult content". Set it from the
group's card in the Clients tab (one window: days + start/end time,
plus its own enable checkbox) or via `client_groups[].schedule`:

```yaml
client_groups:
  - name: "Kids"
    match: ["192.168.1.50"]
    schedule:
      enabled: true
      timezone: ""            # blank = container's local time (set TZ in docker-compose.yml)
      windows:
        - days: [0, 1, 2, 3, 4, 5, 6]   # Monday=0 .. Sunday=6
          start: "22:00"
          end: "07:00"
```

A window is checked against the group's clients on every query - it beats
even the group's own allowlist while active (the point of a bedtime block
is that it's total), the same way `blocked_clients` beats everything;
neither check is affected by the group's own `enabled` flag (that flag
only turns the group's *blocklist/allowlist* membership on or off, not
`blocked_clients` or an active schedule). `start`/`end` can wrap past midnight (`22:00`-`07:00`
above spans two calendar days); the `enabled` flag turns the whole thing
off without losing the saved window, and defaults to off for a group that
doesn't set it, so this is fully opt-in.

### Blocking a client entirely

`blocked_clients` is a separate, stronger mechanism from everything above:
an IP/CIDR (or `mac:`/`host:` pattern, same syntax as `client_groups.match`
above) here has *every* query blocked, for *every* domain - "no
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

### Blocking a destination IP, even for an allowlisted domain

`blocked_answer_ips` (Settings -> Own lists -> "Blocked destination IPs")
is checked after a query actually resolves, against every A/AAAA address
in the answer - regardless of whether the domain itself is on the
allowlist. A domain allowlist entry only ever protects against
*domain-name* matching (the blocklists, `denylist`, the regex denylist);
it was never meant to guarantee that whatever IP that domain happens to
resolve to right now is safe, and a compromised or rebound domain can
resolve to a different, malicious IP at any time without its name ever
changing. This list catches that case: add a known-bad IP/CIDR here and
any query resolving to it gets blocked (NXDOMAIN/null_ip, same as any
other block), even for a domain you've explicitly allowlisted. Checked on
every serve, including cached answers, so adding an entry here takes
effect immediately without waiting for a TTL to expire. Doesn't apply to
[custom DNS records ("rewrites")](#custom-dns-records-rewrites) - those
are IPs you configured yourself, not something DNS-shield resolved from
the internet.

```yaml
blocked_answer_ips:
  - "203.0.113.5"
  - "203.0.113.0/24"
```

Beyond the manual list, "Malicious-IP lists" in that same section lets you
subscribe to a URL the same way as Blocklists: one IP or CIDR per line
(`#`/`!`/`;` for comments, everything else auto-parsed - most public
threat-intel IP feeds already look like this), fetched/cached/refreshed
on the same `blocklists.refresh_interval_hours` schedule as the domain
blocklists, with the same fetch-failure fallback to the last good cached
copy. Matching is O(1) for an exact IP and a short linear scan for CIDR
ranges, computed once per refresh rather than per query, so a large
subscribed feed doesn't add per-query overhead.

```yaml
blocked_answer_ip_sources:
  - name: "Example threat feed"
    url: "https://example.org/malicious-ips.txt"
    enabled: true
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
traffic. It's periodically saved to `data/dns_cache.json` (every 5 minutes)
and reloaded from there on startup, so entries survive a restart as long
as their TTL hasn't expired in the meantime. The Stats tab shows current entry count and
hit rate; Settings -> DNS answer cache has a "Clear cache" button to
empty it on demand (e.g. right after changing upstreams, to stop
serving anything answered by the old one).

### Local "blocked" page

With `dns.block_mode: "null_ip"`, a blocked domain normally just times out
or refuses the connection at `blocked_ipv4` - technically correct, but not
very informative for whoever hit it. Turn on `dns.block_page_enabled` and
DNS-shield itself serves a small "this domain is blocked" page instead:
point `blocked_ipv4` at this host's own reachable LAN IP, and a
plain-HTTP request for a blocked domain lands on `dns.block_page_port`
(80 by default) and gets a page naming the domain (read straight from the
request's own `Host` header) **and why it's blocked** - the same reason
string the query log's (i) icon shows (see
[Query log browser](#query-log-browser-quick-block-and-quick-hide) below
for the full list of possible reasons) - looked up against your
*current* config rather than whatever was true when the DNS answer was
originally given.

This only ever works for plain HTTP. **HTTPS can't be shown a page this
way** - the browser fails the certificate check before it ever sends the
request, which is a fundamental limit of DNS-level blocking, not
something to work around here; doing so would mean terminating TLS with a
certificate the client doesn't trust, i.e. a MITM, which this project
deliberately doesn't do. Off by default; changing either field requires a
container restart, same as the DNS listen address/port.

Running in Docker: with the shipped `docker-compose.yml`'s host
networking (see
[Networking: host mode by default](#networking-host-mode-by-default)),
this is reachable from other devices as soon as you enable it - no port
mapping to add. If you've switched to bridge networking instead, publish
whatever `block_page_port` you set yourself to actually reach this from
other devices on your network.

### Query log browser, quick-block, and quick-hide

The dashboard's **Query log** section searches the full retained history
(not just the last few entries) - filter by domain substring, client
(IP or resolved name) substring, record type, blocked/allowed, and a time
range, with pagination via "Load more". The **Time** column (here and in
the Alerts tab) always shows the full date *and* time, in your browser's
own locale and timezone, so entries from different days can't be
mistaken for each other. The **group** selector narrows the log to the
clients of one [client group](#per-clientgroup-policies) (or to **No group
(default policy)**, the clients no group matches), and every row of a
grouped client shows its group name under the address. Membership is
decided the same way the DNS server decides it - the most specific
matching group wins, including `mac:` and `host:` patterns - using each client's *current*
match, so a client moved to another group shows up under the new one for
its whole logged history. While a group is selected, the **client** selector lists only that
group's clients (so you can't pick a client that would give an empty log),
and a client that is not in the chosen group is deselected automatically.
A restricted user only sees groups that contain
clients they are allowed to see. The same filter is available as
`GET /api/query-log?group=NAME` or `?no_group=true` (and the same parameters on
`GET /api/query-log/clients` for the client list). Each row has a **Block**/**Unblock**
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

**Delete all logged queries** (Settings -> Cleans) wipes every row from
`stats.db` - a full reset of the query log, not a filtered delete.
Irreversible; the dashboard asks for confirmation first.

A blocked row also shows an (i) icon - hover it to see exactly why that
query was blocked: which blocklist subscription matched (by name), a
manual denylist entry (global or a specific client group's), the
non-Latin-script filter, a manually blocked client, an active bedtime
schedule, CNAME cloaking, DNS rebinding protection, a blocked destination
IP, or an experimental regex-denylist pattern - whichever mechanism
actually fired. This is computed at query time and stored per
row (a `reason` column on `stats.db`, backfilled as `null` for rows
logged before this existed - hover shows nothing for those).

Every domain and client address in the log also has a **Copy** button next
to it, for grabbing the exact value onto your clipboard (e.g. to paste into
a search, a firewall rule, or a ticket) without having to select the text
by hand. A client's address also gets a **Block host** button - see
[Blocking a client entirely](#blocking-a-client-entirely) above.

When known, the actual A/AAAA address handed back to the client for that
query shows right under its domain (e.g. `→ 93.184.216.34`), with its own
Copy and Enrich buttons - a different lookup target from the domain itself,
so its Enrich result is independent (a domain's reputation isn't the same
question as whatever IP it happened to resolve to just now). This is the
null IP for a `null_ip`-blocked query, a rewrite's IP, a cache hit's IP, or
the first A/AAAA record in a real upstream reply (any CNAME hops are
skipped) - and is left out entirely for an NXDOMAIN block or a non-address
query type (MX, TXT, ...), where there's nothing to show. Stored per row
(an `answer_ip` column on `stats.db`, backfilled as `null` for rows logged
before this existed - nothing shows for those).

### Stats tab

A **Query trend** chart leads the tab: total vs. blocked queries over
time, with a range filter (last 24 hours, 7 days, or 30 days) that
re-buckets the same `stats.db` history server-side (hourly/6-hourly/daily
points respectively) rather than just re-slicing whatever the last query
already fetched. Hover (or touch-drag on mobile) any point for the exact
count at that moment. No new data is collected for this - it's the same
query log every other table on this tab already reads, just aggregated
differently.

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

### Client-domain graph

The **Graph** tab visualizes which clients query which domains as a
force-directed node graph - clients on one side, domains on the other,
an edge for every client/domain pair that's ever been queried. It's
loosely inspired by JPCERT's [LogonTracer](https://github.com/JPCERTCC/LogonTracer),
which does the same kind of host-account graphing for Windows logon
events to spot lateral movement; this is a much simpler cousin of that
idea applied to DNS query patterns instead, not a reimplementation - there's
no PageRank, no HITS, and no graph database behind it, just a plain
weighted-edge table and a degree-based heuristic (below).

Domains are grouped by **registrable domain**, not naively by the last
two labels: `app/domain_suffix.py` runs every query name through
[`tldextract`](https://github.com/john-kurkowski/tldextract) in fully
offline mode (`suffix_list_urls=()`, a bundled public-suffix-list
snapshot only, no network fetch ever) before it's plotted, so
`sub.deep.example.co.uk` and `other.example.co.uk` collapse into one
`example.co.uk` node instead of incorrectly splitting on `co.uk` as if
it were the registrable domain. Reverse-DNS lookups (`*.in-addr.arpa`/
`*.ip6.arpa`) are excluded entirely, since resolving a PTR record isn't
really a "visit" to anything.

This relationship history lives in its own store, `data/graph.db`, kept
entirely separate from `stats.db` and its `logging.retention_days`
pruning - a background thread polls for newly-logged queries every ~10
seconds and folds them into a running per-(client, domain) count, so the
graph keeps a client's long-term relationship history intact even after
the query log itself has pruned or cleared the underlying raw queries.

Each node - client or domain - gets a **degree** (its number of distinct
edges: how many different domains a client has queried, or how many
different clients have queried a domain) and can be flagged
**suspicious**: DNS-shield computes a z-score of that degree against the
population of same-type nodes (clients compared to clients, domains to
domains) and flags it once the score clears `graph.suspicious_zscore`
(default **2.5**) *and* its raw degree is at least
`graph.suspicious_min_degree` (default **15**, a floor so a node with
only a handful of edges can't get flagged purely for standing out in a
mostly-quiet network) - a client resolving far more distinct domains
than everyone else, or a domain resolved by far more distinct clients
than everyone else, is what this is meant to surface. Both thresholds
are configurable from the dashboard (they're admin-only settings,
`PATCH /api/settings/graph`) and are intentionally simple: this is a
degree/z-score heuristic, not the graph-theoretic centrality analysis
(PageRank, HITS) that a tool like LogonTracer's Neo4j backend can do -
good enough to point at "this node looks
unusual," not a substitute for actually looking at what it queried.

The **View** selector switches between three layouts of the same data:
**Clients and domains** (the default - every client linked to the
domains it queried), **Domains** (domains linked to each other when the
same clients query them, so you can see which sites belong together) and
**Clients** (clients linked when they query the same domains). The
similarity behind a link is the cosine of the two nodes' per-neighbour
query counts, each node keeps only its three closest neighbours so a busy
network doesn't turn into a hairball, and a simple label-propagation pass
colours the groups that behave alike (suspicious nodes stay red). A
restricted user's projection is computed from the clients they may see
only. The same filters, search and drill-down work in every view;
`GET /api/graph?view=bipartite|domains|clients` returns the data.

The canvas itself is a hand-rolled force-directed layout (same
philosophy as the inline-SVG query-trend chart above - no external
charting library) with a **search box** (filter to a client IP or
domain), a **minimum queries per edge** filter to declutter a busy
graph, a **"suspicious nodes only"** toggle that dims everything else
without removing it, and click-to-drill-down: clicking a node opens its
detail (every domain a client has queried, or every client that's
queried a domain, with counts) in the side panel. Scroll (or pinch, on
touch devices) to zoom in and out centered on the pointer, drag the
background to pan, drag a node to reposition it, and double-click (or
the **Reset view** button) to snap back to the default zoom/pan - handy
once a busy network has spread the graph out further than the canvas
can show at once. The layout cools down and settles on its own within a
few seconds, however many relationships or queries per edge a busy
network has: dot size shrinks as the graph gets denser so dots never pile
on top of each other, and only suspicious, hovered, selected, or
zoomed-in nodes carry a label. Dragging a node ends when you release the
mouse button anywhere, even outside the canvas. An admin-only **Clear graph data** button (`POST
/api/graph/clear`) wipes `graph.db`'s entire relationship history - it
has no effect on the query log itself, only on the graph's own memory of
who's talked to whom.

Like Logs and Stats, the Graph tab is gated behind its own permission -
**Can see the client-domain graph** (`view_graph`) - and a restricted
User only granted that permission sees a graph filtered down to their
own **allowed clients / groups**, the same server-side filtering
[Multi-user accounts, roles, and the public view](#multi-user-accounts-roles-and-the-public-view)
below already applies to Logs and Stats.

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

**Seven more public sources** sit alongside those three under the same
switch and the same gate (most need a free-tier key; two don't - see
below):
[GreyNoise](https://www.greynoise.io/) and [Shodan](https://www.shodan.io/)
(both IP-only) add internet-scanning classification (is this address
noise, a known-benign business service, or something actively malicious)
and exposed-service recon (open ports, known CVEs, abuse tags)
respectively; [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch, works for
both domains and IPs, needs a free Auth-Key from their site) checks
whether the indicator has hosted known malware URLs, live or historical;
[ipinfo.io](https://ipinfo.io/) (IP-only, its own on/off toggle under
Settings -> Threat intelligence since it works with or without an API
key) adds geolocation and network/organization info; an **AI summary**
(IP or domain, needs a Gemini API key and its own `ai_enabled` toggle)
asks Gemini for a short, factual summary of who likely owns/operates the
indicator and what it's normally used for, with the query result itself
passed to the model as data to analyze, not as instructions.
**RDAP domain/IP lookup** and **[crt.sh](https://crt.sh/) certificate
transparency** are the two exceptions to needing an API key at all -
both free public lookups with no account or key, gated only by their own
on/off toggle (still behind the public-lookups switch, since they're
still third-party calls); RDAP's toggle defaults to **on** since it costs
nothing and needs no credentials, while every other source (including
crt.sh) still defaults to off. RDAP flags a domain that was registered
suspiciously recently - the same instinct behind
[Typosquat detection](#typosquat-detection) above, a fresh registration
next to a near-miss brand name is a classic phishing tell - and also
surfaces the registrar and, when the registry publishes one and it isn't
redacted for privacy (common under GDPR/ICANN policy, and filtered out
rather than shown as if it were real), the registrant/owner organization
or name. For IP targets, RDAP instead reports the network name, country,
allocated CIDR block, and organization on record. If a domain's RDAP
lookup fails outright (no RDAP record, registry not covered by the
bootstrap service, etc.), DNS-shield automatically falls back to legacy
WHOIS (raw port 43, via the standard IANA-referral chain) to still
surface a registrar/owner/expiry where possible - also free, no API key,
same on/off toggle. crt.sh (domain-only) just reports how many
certificates and distinct subdomain names are on record for the domain,
for your own reference. All ten public sources
degrade the same way: skipped (not an error) for a target type they
don't support, shown as disabled while the public-lookups switch is off,
shown as unconfigured while their own key/toggle is off, and shown as
failed with a plain-language reason if the call itself doesn't succeed
(bad key, rate limit, no data on record, unreachable).

A saved key's status line in Settings shows its first and last character
(e.g. `a***********f`) rather than just "configured" - enough to recognize
*which* key is saved (say, if you keep more than one VirusTotal account)
without the full value ever being sent back to your browser; the key
itself is masked server-side and never round-trips in full once saved.

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

For an IP target that's a client that has queried DNS-shield (the query
log/Stats client column, and the client-groups editor, always mean this;
the query log's resolved-IP-under-domain display, see
[Query log browser](#query-log-browser-quick-block-and-quick-hide) above,
is the one case where an IP target is instead whatever address a domain
happened to resolve to - not a client, so no block control makes sense
for it) - the popup has a **Block this host**/**Unblock this host**
button, the same feature as the query log/Stats "Block host" button, just
reachable without leaving the popup; see
[Blocking a client entirely](#blocking-a-client-entirely) above for what
it actually does.

For a **domain** target that came back an overall **safe** verdict, the
popup also has an **Add to allowlist** button - a shortcut for the exact
same cleanup the query log's Unblock button does (see
[Query log browser](#query-log-browser-quick-block-and-quick-hide) above):
clears any manual denylist entry for it first, then adds it to the global
allowlist, since a denylist entry always wins over the allowlist and would
otherwise silently keep it blocked. Not offered for IP targets - DNS-
shield's allow/denylist match query *names*, not IP literals, so there's
no equivalent "allowlist this IP" action to offer.

A lookup that comes back medium-or-worse (configurable, Settings ->
Threat intelligence -> "Add an Alert when a lookup comes back with a bad
reputation") also adds an entry to the **Alerts** tab, same place local
anomaly detection and alert-rule hits land - see the next section.
Repeat lookups on the same bad indicator respect the same re-alert
cooldown as everything else in Alerts (Settings -> Anomalies ->
"Re-alert cooldown"), so clicking Enrich on a domain you already know is
bad ten times in a row doesn't create ten identical entries.

### Automatically enriching newly-seen domains

Enrich is otherwise entirely manual - see above - but Settings -> Threat
intelligence -> "Automatically enrich newly-seen domains" (off by
default) adds one exception: the first time DNS-shield ever sees a query
for a given domain, it runs Enrich for it in the background, on the
theory that a domain nobody on your network has ever queried before is
exactly the moment a new threat is most likely to show up unblocked and
most worth a reputation check. Every query after that first one is
ignored for this purpose - once a domain's been checked, it's never
auto-enriched again, so this doesn't turn into a lookup on every single
query.

This still needs "Enable public lookups" (or a local reputation service)
switched on to actually call anything, same gate as a manual Enrich - the
automatic part is only ever *which* domains get checked and *when*, never
a way around that switch. A background check every 30 seconds (both
configurable) looks at whatever's been queried since the last check and
enriches up to 5 newly-seen domains from it (also configurable) - capped
deliberately, so a burst of new domains all at once (a device coming
online, a phone restoring its apps) can't blow through a free-tier API
quota in one go; it just falls behind and catches up over the next few
checks instead of enriching everything at once or silently dropping the
overflow. "Newly seen" survives a restart too: it's based on whether a
domain has ever been recorded in `enrichment.db` (see below), not an
in-memory list, so restarting the container doesn't reset every domain
back to "new" and re-check your whole history.

Every Enrich result - manual or automatic - is recorded in
`enrichment.db`: target, timestamp, overall verdict/score, and the raw
per-source responses, kept indefinitely so a domain's reputation history
is there to look back on. A result triggered this way is marked
`source: "auto"` (a manually-clicked one is `"manual"`) - visible as a
"How" column in the Enrich popup's lookup-history table, and in
`GET /api/enrich/history`, so it's always clear whether a given check
happened because you clicked something or because DNS-shield noticed the
domain on its own.

### Alerts tab, and local anomaly detection

Everything DNS-shield flags on its own - a local anomaly-detection hit, a
watched domain/list match ([Alert rules](#alert-rules-watched-domains-and-lists)
below), or a bad-reputation threat-intel lookup (previous section) - lands
in one place: the **Alerts** tab. Three checkboxes above the table
("Anomalies" / "Alert rules" / "Threat intelligence", all on by default,
remembered per browser) filter the list down to just the source you care
about, and a **Source** column tags each row the same way. This is
purely a display grouping - all three still write to the same underlying
alert store, share the same acknowledge/delete/clear actions, and the
unacknowledged-count badge on the tab counts across all of them together.

A domain-specific alert row (a watched domain, a typosquat match, a
rebinding hit, a local-TLD query) can be shut off for good from the
alert itself: "Show domains" opens a popup listing the domains behind
it, each with its own **Enrich** button for a reputation check, and now
an **Exclude** button right next to it - one click adds that domain (and
its subdomains) to Settings -> Anomalies -> "Excluded from anomaly
detection", so it never raises a watched-domain/typosquat/rebinding/
local-TLD alert again. It doesn't touch the volumetric checks (query
bursts, blocked ratio, DNS tunneling, PTR scanning) - those flag a
client's overall behavior across many domains, not any one domain, so
there's no single-domain exclusion that would make sense there; use the
threshold settings above instead if one of those is too sensitive for
your network. The same list is editable directly in Settings if you'd
rather add a domain without waiting for it to alert first.

### Local anomaly detection

Settings -> Anomalies configures an optional background check over your
own query log for a handful of simple, per-client statistical red flags -
no ML, no cloud call, nothing beyond arithmetic over data already
sitting in `stats.db`. **Off by default.** Turn it on and DNS-shield
re-checks recent activity on a timer (`anomaly.check_interval_minutes`,
default every 5 minutes) over a rolling look-back window
(`anomaly.window_minutes`, default 15 minutes), independently for every
client that's queried it in that window:

- **High blocked-query ratio** - a large share of a client's queries in
  the window were blocked. Classic sign of a compromised app/device
  hammering ad/tracker/malware domains. Only evaluated once a client has
  made at least `anomaly.min_queries` (default 20) queries in the
  window, so a handful of queries can't trip it on a tiny sample.
- **Distinct-domain burst** - a client resolved an unusually large
  number of *distinct* domains in the window (`anomaly.domain_burst_threshold`,
  default 50), **and** a meaningful share of those domains look randomly
  generated rather than real words. Typical of DGA (domain generation
  algorithm) malware cycling through candidate command-and-control
  domains. "Looks randomly generated" is Shannon entropy of each
  domain's own label (e.g. `kq7xzpqm3f` out of `kq7xzpqm3f.info`) -
  scored only on labels at least `anomaly.domain_burst_min_label_length`
  characters long (default 10; shorter labels are too noisy to score
  reliably) against a randomness threshold
  (`anomaly.domain_burst_min_entropy`, default 3.3 bits/character); the
  burst only fires once at least `anomaly.domain_burst_entropy_fraction`
  (default 50%) of the distinct domains clear that bar. This second gate
  is what keeps an ordinary high-cardinality burst - a page pulling in
  thirty different *real* ad/tracker vendor domains, which is a
  distinct-domain burst too - from being flagged: real words consistently
  score lower than genuinely random strings of similar length, even
  though character-level entropy alone is an approximation, not a
  certainty, for any single domain.
- **Distinct-blocked-domain burst** - a client hit an unusually large
  number of distinct *blocked* domains in the window
  (`anomaly.blocked_domain_burst_threshold`, default 15) - a stronger
  signal than the ratio check alone, since it can't be explained by one
  ad-heavy page reloading the same handful of ad domains.
- **DNS tunneling** - a client queried an unusually large number of
  *distinct subdomains of the same domain* in the window
  (`anomaly.dns_tunneling_threshold`, default 30), most of which look
  long and random rather than a real site's normal handful of
  subdomains - the same entropy scoring as the domain-burst check above,
  but applied to the first label of each subdomain instead of a whole
  domain (`anomaly.dns_tunneling_min_label_length`, default 20;
  `anomaly.dns_tunneling_min_entropy`, default 3.0 bits/character). DNS
  tunneling abuses DNS as a covert data channel by encoding a chunk of
  data into a unique subdomain per query
  (`k3f9a...92mz.tunnel.example.com`, one query per chunk) - this is the
  enterprise DNS-security detection technique for that, applied to
  domain *counts* rather than raw traffic volume, so it needs no new
  data beyond what's already logged. The distinction from the
  distinct-domain burst above: that one fires on many different
  *domains* (DGA malware trying candidate C2 domains), this one fires on
  many different *subdomains of one domain* (data being smuggled out
  through one attacker-controlled domain).
- **Subdomain count burst** - a client queried an unusually large number
  of *distinct subdomains of the same domain* in the window
  (`anomaly.subdomain_count_threshold`, default 50), with **no**
  randomness filter at all - a plain count. This is deliberately
  separate from DNS tunneling above: tunneling's entropy gate means it
  only fires when the subdomains look encoded/random, so it misses
  low-entropy patterns like sequential or enumerated subdomains
  (`host1.example.com`, `host2.example.com`, ...), subdomain
  brute-forcing/enumeration, or wildcard/CDN abuse that doesn't happen to
  look "random". Because there's no pre-filter, legitimate
  high-subdomain-count infrastructure (CDNs, mail systems, cloud
  services) can also trip this, so the right threshold is network-
  specific; Settings -> Anomalies has an "Analyze saved data" tool next
  to this setting that ranks the base domains in your own query log by
  distinct-subdomain count over a chosen window (last hour/24h/7 days,
  top 20), so you can see what's normal for your network before picking
  a number. Excluded domains (see below) never show up in this ranking
  in the first place - once you've decided a domain is fine, there's no
  reason to keep seeing it here. Each remaining ranked domain has a
  **Show subdomains** button (opens the actual subdomain names in a new
  window, with a copy-all button) and an **Ignore** button, which adds
  it to `anomaly.subdomain_count_excluded_domains` and removes it from
  the list immediately. That exclusion list has its own dedicated
  Settings section, "Ignored subdomain-count domains", right below the
  general "Excluded from anomaly detection" list - add, remove, or
  review entries there directly, without needing to re-run the
  analysis. It's a separate list from that general exclusion list,
  which explicitly doesn't cover this or the other volumetric checks.
- **PTR scan** - a client issued an unusually large number of reverse-DNS
  (PTR) lookups against *private/local* IP addresses in the window
  (`anomaly.ptr_scan_threshold`, default 15) - one device methodically
  asking "who is 192.168.1.1? who is 192.168.1.2? ..." looks like a
  network-mapping tool enumerating hosts on the LAN, not normal browsing.
  Only private-range targets count (decoded from the reversed
  `in-addr.arpa`/`ip6.arpa` query name), since PTR lookups against public
  IPs are unremarkable; severity escalates from `medium` to `high` at
  double the threshold.

Every flagged anomaly is stored locally in `data/anomalies.db` and shown
in its own top-level **Anomalies** tab (between Logs and Stats, with an
unacknowledged-count badge), with the client, what tripped, a
human-readable summary, and (reusing the same buttons as the query
log/Stats/Enrich popup) quick **Enrich**/**Block host** actions on the
client IP - **Acknowledge** to dismiss it from the default view without
deleting it, or **Remove** to delete it outright; **Clear all** wipes
the table. Settings -> Anomalies holds the configuration (thresholds,
watched domains/lists) - the same split as the Logs tab (data) vs.
Settings -> Logging (config).

A **Show domains** button on any row opens a popup listing the actual
domain names behind that anomaly's aggregate count (e.g. which 12
domains made up a "12 distinct blocked domains" hit) - reconstructed on
demand from the query log for that client and time window, not stored
redundantly on the anomaly itself. For **DNS tunneling** and
**subdomain count burst** specifically, this list is further narrowed
to just the subdomains of the one base domain that tripped the alert
(the client's other, unrelated traffic in that window is excluded),
since those two checks are about one domain's subdomains, not the
client's activity as a whole.

A **subdomain count burst** alert also has an **Ignore domain** button
right on its row (no need to open "Show domains" first) - it adds the
alert's base domain to `anomaly.subdomain_count_excluded_domains` (the
same list the "Analyze saved data" tool's Ignore button and the
Settings -> Anomalies -> "Ignored subdomain-count domains" list use)
and removes this specific alert, since it can never fire the same way
again. A domain on
`logging.ignored_domains`/`ignored_clients` never appears here, for the
same reason it never appears in the query log at all: it's never written
to `stats.db` in the first place (Settings -> Logging -> "Excluded from
the log").

A **Check now** button runs a check immediately instead of waiting for
the timer, handy right after changing thresholds. **Reanalyse** does
something different: pick a historical range (12/24/48 hours, or 7/14/30
days) and it walks that whole range in `anomaly.window_minutes`-sized
slices, re-running the exact same heuristics against each slice as if
the detector had been ticking continuously throughout that period -
useful after changing thresholds, or to audit a stretch of history you
didn't have detection turned on for. The per-client/anomaly-type cooldown
still applies, in chronological order, so a burst spanning several
consecutive slices only fires once. It never sends a notification for
what it finds (a retroactive audit isn't a live event worth paging
anyone about), though results still land in the normal anomalies list,
timestamped to when the historical activity actually happened rather
than when you ran the reanalysis. A range of 7 days or longer scans a
real amount of data and can take a while - the dashboard warns about
this before running one.

A persistent condition doesn't spam a fresh row every cycle: once a
given client/anomaly-type combination fires, it's suppressed for
`anomaly.cooldown_minutes` (default 60) before it can fire again.

This runs entirely on its own background thread, decoupled from DNS
resolution - it only ever reads `stats.db` on a timer and writes to its
own `anomalies.db`, never touching the query-answering path at all. A
bug here can, at worst, stop producing new alerts; it cannot break or
slow down DNS resolution.

### Typosquat detection

Settings -> DNS has a separate "Detect typosquatting" toggle (also off by
default) that checks every query against a list of well-known brand
domains for two things a real visit to that brand would never produce:

- **A close spelling variant** - one or two characters off from the real
  domain (`paypa1.com`, `faceb00k.com`, `gooogle.com`), measured as
  [Levenshtein edit distance](https://en.wikipedia.org/wiki/Levenshtein_distance)
  between the queried domain's own label and the protected domain's,
  within `dns.typosquat_max_distance` (default 2).
- **The brand name embedded in a longer domain** -
  `paypal-security-check.com`, `secure-allegro-login.pl`,
  `paypal123.com`, and even a brand blended into another word with no
  separator at all (`paypalsecurity.com`, `secureallegrologin.pl`) - a
  classic combosquatting pattern edit distance alone won't catch, since
  inserting a dozen extra characters is a large distance even though the
  brand name is sitting right there unmodified. For a short protected
  name (`chase.com`, `apple.com`, under 6 characters) this only fires
  when it's set off by a hyphen, a digit, or the start/end of the label
  - `purchase-receipts.com` and `pineapple-farm.com` are correctly left
  alone - since an unbounded match on a short brand name collides too
  often with ordinary words it happens to be a substring of. A short,
  curated list of known-legitimate compounds (`googleapis.com`,
  `amazonaws.com`, `githubusercontent.com`, `paypalobjects.com`,
  `microsoftonline.com`, and a handful of others) is also exempted
  outright, since there's no reliable way to tell those apart from a
  real combosquat by pattern alone.

An exact match or a real subdomain of the protected domain itself
(`mail.google.com`, `accounts.google.com`) is explicitly never flagged -
only something that's *close but not actually it*. A match always raises
an alert through the same pipeline as the anomaly heuristics above
(visible in the Alerts tab, notification-capable, its own per-client/domain
cooldown - `dns.typosquat_cooldown_minutes`, default 30); `dns.typosquat_action`
(also Settings -> DNS) separately controls what happens to the *answer*:

- `"alert"` (default) - resolve the queried domain normally. The alert is
  the only effect; nothing about the answer changes.
- `"redirect_real"` - resolve the *protected* domain's own real address
  and hand it back under the name that was actually queried, so a client
  that typed `paypa1.com` transparently lands on the real PayPal instead
  of whatever `paypa1.com` actually points to. Uses the same
  resolve-a-different-hostname mechanism as
  [forced SafeSearch](#parental-control--safesearch) above, including
  going through the answer cache the same way.
- `"redirect_custom"` - always answer with one fixed address you set in
  `dns.typosquat_redirect_ip`, e.g. a local page explaining what
  happened (you'd run that page yourself - DNS-shield doesn't ship one).
  Falls back to normal resolution if the field is left blank rather than
  answering with nothing.

`"redirect_real"` is a judgment call worth being explicit about: it's
convenient (a mistyped brand name quietly still works) but it also means
DNS-shield is guessing what the user *meant* to type rather than just
reporting what they *actually* queried - reasonable for an honest typo,
less reasonable if you'd rather a human looked at every hit before
anything auto-resolves differently. `"alert"` keeps that judgment with
you; a close-but-wrong guess is a real signal, not a certainty, and
false positives here would land on legitimate traffic (a domain that
happens to be a couple of characters from a brand name for entirely
unrelated reasons) rather than being silently absorbed the way an
over-broad blocklist entry might be.

Own lists -> Typosquat protection shows the built-in list of ~50 protected
domains (major tech/finance/shipping brands plus a handful of commonly-
targeted Polish services - banks, Allegro, InPost, mobile carriers) and
lets you add your own on top - your own company's domain, say. This list
is additive-only by design, the same reasoning as a client group's extra
blocklist sources: you can make the check cover more, not silently drop
one of the curated defaults.

This is a per-query, real-time check (unlike the window-based heuristics
above), but a cheap one: distance is only computed against ~50 short
strings, and results are cached per distinct domain so a repeat query
never redoes the comparison - the cache is cleared automatically whenever
the protected-domains list or max-distance setting changes.

### Query access control (recursion ACL)

Settings -> DNS -> "Query access control" (on by default,
`dns.query_acl_enabled`) restricts who the resolver will actually answer,
independent of `dns.listen_address` - the two solve different problems.
`listen_address` picks which network interface DNS-shield binds to;
without a separate check on *who's asking*, binding to `0.0.0.0` (needed
for LAN clients to reach it at all) also means anyone who can route a
packet to that address - including the open internet, if the host is
directly exposed - gets a full recursive answer, the classic "open
resolver" misconfiguration that gets abused as a DNS-amplification
reflector against third parties and as a cache-poisoning target. With
the ACL on, a query from a private/LAN address (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, loopback, link-local, and their IPv6
equivalents) is answered normally; anyone else gets `REFUSED`
immediately, before any blocklist/cache/upstream work happens. Add a CIDR
or single address to `dns.query_acl_extra_networks` for a legitimate
case outside those ranges (a VPN subnet like Tailscale's `100.64.0.0/10`,
a remote monitoring host) rather than turning the whole thing off; the
toggle exists for anyone who explicitly wants an open resolver, but that
should be a deliberate choice, not the default.

### DNS rebinding protection

[DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) is an attack
where a domain the victim's browser trusts (because they just navigated to
it) is made to resolve to a private/internal IP address, so JavaScript
served from that domain can reach into the victim's own LAN - a router's
admin panel, a NAS, an internal API - past same-origin protections that
would normally stop a public web page from doing that. Settings -> DNS has
a "DNS rebinding protection" toggle (**on by default**) that catches this
at resolution time: every A/AAAA answer coming back from upstream is
checked against [`ipaddress.is_private`](https://docs.python.org/3/library/ipaddress.html)
(covers RFC1918, loopback, link-local, and IPv6 ULA in one call), and if a
queried domain resolves to a private address, `dns.rebinding_action`
decides what happens to that answer:

- `"block"` (default) - answer as blocked instead, the same shape as a
  blocklist hit, with the reason recorded as `DNS rebinding protection
  (<ip>)`.
- `"alert"` - resolve normally, just raise an alert. Nothing about the
  answer changes.

Two things are exempt from this check entirely, since they *legitimately*
resolve to private addresses: domains under the same local-TLD list used by
[Local-TLD query alerts](#local-tld-query-alerts) below (`.local`, `.lan`,
`.home`, etc. - a router or NAS answering its own hostname on the LAN isn't
rebinding), and anything you list yourself under
`dns.rebinding_exempt_domains` (and its subdomains) for your own internal
services that are supposed to resolve locally. A hit also lands in the
Alerts tab as its own `high`-severity row (same cooldown/notification
pipeline as every other anomaly here, via `anomaly.cooldown_minutes`), so
`"alert"` mode still gets you paged even though the DNS answer itself goes
through untouched.

### Local-TLD query alerts

A separate, unrelated toggle in Settings -> DNS - "Local TLD query alerts",
also off by default - logs when a client queries a domain under one of
those same local-only TLDs (`dns.local_tld_list`, defaults to `local`,
`lan`, `home`, `internal`, `corp`, `home.arpa`). It only fires for clients
with a non-private source IP - ordinary LAN devices (the typical source of
mDNS/homenet traffic, and completely normal there) never trigger it by
design; this is for noticing a *public* IP querying one of those suffixes,
which is unusual enough to be worth a look. It's a low-severity,
informational row in the Alerts tab, with a cooldown
(`dns.local_tld_cooldown_minutes`, default 30) keyed per client and TLD -
not per individual domain, so repeated queries for different hostnames
under the same TLD from the same client still only alert once per cooldown
window. Leave it off if you don't need this.

### Alert rules (watched domains and lists)

The four heuristics above are statistical guesses over a rolling window -
useful for "something looks off", but not for "tell me the instant this
*specific* domain gets queried". Alert rules cover that instead: still in
Settings -> Anomalies, right below the anomaly-detection settings, is a
"Watched domains & lists" section where you list exact domains (and their
subdomains) and/or subscribe to watch lists (same hosts/AdBlock/plain
formats, fetch/parse/cache behavior as the global Blocklists section -
see [Blocklist formats and suggested lists](#blocklist-formats-and-suggested-lists)
above). A dropdown lets you watch a list that's already configured in
Blocklists with one click (it drops off the dropdown once watched, same
as the Suggested-lists catalog); there's also a plain name/URL form right
below it for watching a list that isn't in Blocklists at all. Querying
anything on either list raises an alert - **whether or
not the query is actually blocked** - and shows up as a "high"-severity
row in the same top-level Alerts tab, going through the exact same
Acknowledge/Remove/Clear-all controls and the same email/browser
notification pipeline described above. No separate on/off switch: an
empty domains/sources list simply never matches anything, the same as
the blocklist/allowlist sources it mirrors. A matching query also gets a
small red "watched" tag next to it in the Logs tab, so you can spot it
without leaving the query log.

Matching itself happens exactly like blocklist matching - a cheap,
in-memory check against a set refreshed on the normal blocklist refresh
cycle (and immediately whenever you add/remove a watched domain or
source from the dashboard) - so it costs nothing extra on the DNS hot
path. What's checked roughly every `alert_rules.check_interval_seconds`
(default 15) is a separate, much lighter background loop: it polls the
query log for newly-logged hits and turns each into an alert, the same
"cheap poll, heavier work stays off the DNS path" separation as anomaly
detection itself. `alert_rules.cooldown_minutes` (default 15) works the
same way as the anomaly detector's cooldown: once a given client/domain
combination fires, it's suppressed for that long before firing again, so
a client repeatedly hitting the same watched domain doesn't flood the
table.

### Notifications

Settings -> Notifications has three independent ways to hear about a newly
detected anomaly without having the dashboard open at the moment it
fires - all off by default, all entirely under your own control:

**Email**, sent straight to the SMTP server *you* configure - your own
mail server, or your own account at any provider - using nothing but
Python's standard library (`smtplib`); this is not a third-party cloud
service, it's exactly what any desktop mail client does. Fill in the
host, port, security mode (STARTTLS/SSL/none), optional username/password,
a from address, and at least one recipient, then **Save email
notification settings**. A **Send test email** button lets you verify
the configuration immediately rather than waiting for a real anomaly.
`notifications.email.min_severity` (default `medium`) limits which
anomalies actually trigger an email, so a flood of low-severity alerts
doesn't flood your inbox too - every anomaly still shows up in the
Alerts tab regardless of this setting, it only affects what emails
out. The SMTP password is masked the same way as the threat-intel API
keys (first/last character only, e.g. `s******t`) and never round-trips
to your browser in full once saved.

**Webhooks**, straight to Discord, Slack, or a Telegram bot - DNS-shield
posts the HTTP request itself (a plain `requests.post`, same library the
threat-intel lookups already use), nothing routes through a third-party
relay beyond whichever of those three services you point it at. Add as
many as you want from the **Webhook notifications** section, each with
its own name, target (a Discord/Slack incoming-webhook URL, or a
Telegram bot token + chat ID), and its own `min_severity` - so a
low-priority stream can go to a quiet Slack channel while only `high`
pages a Telegram chat, say. Each entry gets its own **Test** button, and
Enable/Disable without deleting it. A Discord/Slack webhook URL and a
Telegram bot token are both masked the same way as the SMTP password
above (they're bearer credentials - anyone holding one can post through
it) and never round-trip to your browser in full once saved; a Telegram
chat ID isn't a secret and is shown in plain text. One webhook failing
(bad URL, revoked token, network error) is logged and never blocks the
others - each is sent independently, same as email is independent of all
of them.

**Browser popups**, via your browser's own
[Notification API](https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API) -
no server component at all. Checking "Notify me in this browser when new
anomalies are detected" asks your browser to allow popups from the
dashboard; once granted, that browser tab polls the dashboard's own
unacknowledged-anomaly count every 30 seconds (as long as the dashboard
is open in some tab) and pops a native notification when that count goes
up. This is a per-browser/per-device choice stored in that browser's own
`localStorage`, not a server-side setting - enabling it on your laptop
doesn't enable it on your phone, and DNS-shield never learns whether
you've turned it on.

The browser's Notification API only works in a "secure context" - HTTPS,
or the dashboard opened via `localhost`/`127.0.0.1`. Opened over plain
HTTP at a LAN address (the default way most people reach DNS-shield),
the browser silently refuses to even show the permission prompt; the
checkbox explains this and disables itself rather than doing nothing
with no explanation. Put a reverse proxy with TLS in front if you want
browser popups from a LAN address.

Both channels only ever fire from the *same* event: a new row landing in
`anomalies.db` from the anomaly detector above. Neither one is itself a
new source of outbound calls beyond what's already documented - email
goes to the mail server you typed in, and the browser popup never leaves
your own browser.

The same Settings -> Notifications page also has a **URL ping (cron)**
section, which is unrelated to anomalies - it's a plain timer, not an
event-driven notification. Turn it on, set a URL and an interval in
minutes (default 15), and DNS-shield sends a plain HTTP `GET` to that
URL on that schedule for as long as it keeps running, using the same
`requests` library the threat-intel lookups and webhooks already use.
Useful for a keep-alive ping against a host that sleeps on inactivity,
an uptime monitor's check-in URL, or simply triggering some other
service's endpoint on a schedule. It's entirely fire-and-forget: the
outcome (the response status, or the error if the request failed) is
only ever written to DNS-shield's own log - nothing else reacts to it,
and a failed ping never affects DNS resolution or any other feature.

### Multi-user accounts, roles, and the public view

DNS-shield supports more than one dashboard account, each with its own
password and its own view of the data - Settings -> Users (Administrator
accounts only).

**Roles.** An **Administrator** sees and does everything: every tab,
every client/group, all Settings, threat-intel Enrich, anomalies, and the
"Blocking active" pause bar. A **User** is read-mostly and limited to
whatever an admin grants them:

- **Allowed clients / groups** - IP/CIDR patterns and/or `client_groups`
  names. A restricted user's Logs, Stats, Anomalies, and Graph are all
  transparently filtered down to just these clients server-side (not a
  client-side hide - the API itself never returns another client's rows
  to them); leaving both empty means the account sees no client data at
  all until an admin grants some.
- **Can see threat-intel results** - without this, Enrich buttons are
  disabled and `/api/enrich` is refused.
- **Can see detected anomalies** - without this, the Alerts tab is
  hidden and its endpoints are refused.
- **Can see the client-domain graph** - without this, the Graph tab is
  hidden and its `/api/graph*` endpoints are refused.
- **Can block a domain/host** - without this, "Block host" and adding to
  the global denylist are refused (per-group denylist editing and every
  other Settings change remain Administrator-only regardless).
- **Can whitelist a domain** - same, for the global allowlist.
- **Can manage reverse-proxy domains / allowed domains** - lets a User
  create, edit, and delete entries under Settings -> Reverse proxy, but
  only for hostnames matching their **allowed domains** list (exact match
  or subdomain, same matching rule as allowed clients above); leaving
  that list empty means the permission grants nothing to manage yet.
  Editing a domain's raw custom-nginx-config escape hatch always stays
  Administrator-only regardless of this permission.

The Settings tab itself, and the "Blocking active" pause bar, are always
Administrator-only - a User account never sees them, and the underlying
API endpoints refuse a non-admin regardless of what the dashboard shows.

**Signing in.** `/login` is a dedicated page (not a browser Basic-Auth
popup), so it can carry its own branding and a "back to the public view"
link. A successful login sets an `HttpOnly` session cookie (`SameSite=Lax`,
no `Secure` flag - this is meant for a plain-HTTP LAN deployment, same as
the rest of the dashboard; put a reverse proxy with TLS in front if you
need `Secure` cookies). Sessions live in server memory only, so a
container restart signs everyone out; changing a user's password (their
own, or an admin changing someone else's) also signs out every session
for that account immediately.

**Signed out**, `/` shows a minimal public view: just the query trend
chart and the top blocked domains list (domain + count, nothing else) -
no client IPs, no query log, no Copy or Enrich buttons, no tabs, no pause
bar. This is meant to be safe to leave open on a shared screen or point a
household member at without giving them a login. It's served by its own
endpoint, `GET /api/public/summary`, which needs no session cookie.

**Passwords** are always bcrypt-hashed (`app/auth.py`), never stored or
returned in plain text. Upgrading from a version that only had a single
`web.username`/`web.password` pair migrates that one account into the new
`users` list automatically the first time the new version starts,
converting its existing password to a bcrypt hash in place - nothing to
redo by hand, and the same username/password keep working. Every user can
change their own password from Settings -> General -> "Your account";
only an Administrator can create, edit, or delete accounts (Settings ->
Users), and DNS-shield refuses to demote or delete the last remaining
Administrator so you can't lock yourself out entirely.

A downloaded config backup (see **Downloading a backup** below) includes
every account's bcrypt hash - not reversible to the original password,
but still worth keeping private, same as any other credential in that
file.

**Two-factor authentication (TOTP)** adds a second step to signing in -
Settings -> General -> "Two-factor authentication", off by default, one
account at a time (each account turns it on for itself, an admin can't
force it on for someone else). Enabling it shows a QR code for any
standard authenticator app (Google Authenticator, Authy, 1Password,
Bitwarden, etc.) plus the underlying base32 key for manual entry if you'd
rather type it in than scan - both encode the same
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) TOTP secret, generated
server-side with `pyotp` and rendered to an inline SVG with `qrcode`
(no Pillow, no external image service - the whole thing is one HTTP
round trip). Confirming with the 6-digit code your app produces enables
it and hands you 8 single-use backup codes, shown exactly once - store
them somewhere safe, since each is worth one login if you lose the
device your authenticator app is on. From then on, `/api/login` returns
`{"totp_required": true, "totp_token": ...}` instead of setting a session
cookie once the password checks out; `/api/login/totp` takes that token
plus a 6-digit code (or an unused backup code) and only then sets the
cookie. A wrong code counts against the same per-IP lockout as a wrong
password (`web.login_max_attempts`/`web.login_lockout_minutes`, see
**Security notes** below) - guessing codes isn't free. Disabling it back
off asks for your current password first, same safeguard as changing it.

**Passkeys (WebAuthn)** are the other second-factor option, alongside
TOTP rather than replacing it - Settings -> General -> "Passkeys". A
hardware security key or a device's own built-in authenticator (Touch
ID, Windows Hello, a phone's fingerprint/face unlock) satisfies the
same "second step" TOTP does, without typing a code: registering one
is enough on its own to require a second factor at login, whether or
not TOTP is also turned on for that account. When an account has both,
the login page offers either - enter a code, or click "Use a passkey
instead" - and if it only has a passkey (no TOTP), the browser's
passkey prompt fires automatically the moment the password step
succeeds, no extra click needed. Built on the
[`webauthn`](https://github.com/duo-labs/py_webauthn) library for the
actual registration/authentication ceremonies (`credential.create()`/
`credential.get()` in the browser, verified server-side against a
challenge that expires after 5 minutes either way), storing each
account's credential public keys and signature counters - never
anything that could be replayed on its own.

This one comes with a real, unavoidable limitation worth knowing before
you rely on it: WebAuthn's relying-party ID has to be an actual domain,
and **browsers reject a bare LAN IP address outright** - registering a
passkey while reaching the dashboard at `http://192.168.1.50:3000`
fails immediately with "This is an invalid domain," confirmed against
Chromium, not a guess. `localhost` works, and so does any real
hostname (a LAN DNS entry, a hosts-file line, a domain through a
reverse proxy) - if you normally reach DNS-shield by typing an IP,
point a name at it first (the dashboard's own address bar will tell
you which hostname it's currently reachable as).

**API tokens** let a script, cron job, or dashboard (Grafana, a Home
Assistant automation, your own tooling) call the API without a browser
session - Settings -> General -> "API tokens". Each token is tied to the
account that created it and acts as that account for every permission
check: an admin's token can do anything an admin can through the API, a
restricted user's token is limited the same way that account already is.
Send it as `Authorization: Bearer <token>` on any request; `GET /metrics`
and the DoH endpoint (`/dns-query`) never need one, since both are
unauthenticated by design (see above) - a token only matters for the
rest of the API. The token itself is a 256-bit random value
(`secrets.token_urlsafe`, prefixed `dnss_` so it's recognizable in a
config file or a `.env`) - only its SHA-256 hash is ever stored, and the
plaintext is shown exactly once, at creation, with nowhere in the UI to
retrieve it again afterward; lose it and you create a new one and revoke
the old. Revoking (or deleting the owning user) invalidates it
immediately - there's no grace period. Like a bcrypt password hash, a
token's hash isn't reversible to the original value, but a downloaded
config backup still includes it, same caveat as **Passwords** above.

**Audit log** (Settings -> Users -> "Audit log") is a running, read-only
record of every successful settings/config change made through the
API - who (which account), what (`METHOD /api/path`), and from which
address, newest first - plus sign-ins and sign-outs. It's built with a
single piece of middleware that watches every `POST`/`PUT`/`PATCH`/
`DELETE` under `/api/`, so new endpoints get covered automatically
without needing an explicit log call added to each one; login/logout
are logged explicitly instead, since a session cookie doesn't exist yet
at the moment a login request arrives. Only requests that actually
succeeded (status under 400) are recorded - a rejected or failed
attempt leaves no entry - and only mutating requests: routine reads
like loading a page or the dashboard's 10-second stats poll never
appear. `GET /dns-query` (DoH) and `POST /dns-query` are deliberately
excluded too - every DNS query would otherwise flood this into
uselessness, and it's meant to answer "who changed what", not to be a
second query log. Stored in its own `audit.db`, pruned on the same
`logging.retention_days` schedule as the query log.

### Single sign-on (SSO / OpenID Connect)

Settings -> Users -> "Single sign-on" lets people authenticate through an
external identity provider instead of, or alongside, a local DNS-shield
password - any provider that speaks standard OpenID Connect works:
Authentik, Keycloak, Authelia, Okta, Google Workspace, Microsoft Entra ID,
and so on. Off by default; turning it on adds a "Sign in with ..." button
to the login page next to the username/password form, never replacing it.

Configuring it needs four things from your provider: the **issuer URL**
(DNS-shield fetches `<issuer>/.well-known/openid-configuration` from it to
discover the authorization, token, and JWKS endpoints - no need to enter
those individually), a **client ID** and **client secret** from an OAuth
application you register there, and the **redirect URI** to register on
that application's side, which the settings page shows you exactly
(`<your dashboard URL>/api/sso/callback`). The rest - scopes, which claim
carries the username, the sign-in button's label, and whether a first-time
sign-in should auto-create a local account (and with which role) - has
sensible defaults you can leave alone.

The flow itself is standard authorization-code OIDC: clicking the button
redirects to your provider with a random `state` and `nonce` DNS-shield
generates and remembers server-side (nothing client-readable, so neither
can be forged or replayed); the provider redirects back with a code,
DNS-shield exchanges it for tokens directly (server-to-server, the
browser never sees the client secret), and verifies the returned ID
token's signature against the provider's own published JWKS key set plus
its issuer, audience, and nonce - only then does a DNS-shield session
cookie get set, exactly like a password login would. Built on
[Authlib](https://docs.authlib.org/) (the OAuth flow) and
[joserfc](https://jose.authlib.org/) (JWT/JWKS verification), the same
kind of well-audited libraries any framework would reach for, rather than
hand-rolled token verification. Only asymmetric signature algorithms
(RS/PS/ES/EdDSA) are accepted - `none` and HMAC tokens are refused - and
the token must carry an expiry (`exp`); a minute of clock skew is
tolerated.

A first successful sign-in for an identity DNS-shield hasn't seen before
creates its local account automatically (the **username claim** setting,
`preferred_username` by default, decides what becomes the username;
falls back to the `email` claim, then `sub`) with the role you picked in
Settings - unless you turn auto-provisioning off, in which case an admin
has to create the account by hand first and SSO only authenticates
existing ones. Either way, an SSO-provisioned account gets a random,
never-shown local password hash, so the password-login path stays
impossible for it - only the identity provider (or a manual password
reset by an admin afterward) can sign it in. An SSO identity can only ever bind to an account that was itself
created via SSO - if the username your provider returns matches a
*local*, password-based account (including the built-in `admin`
account), DNS-shield refuses the login outright rather than signing
into that account, since the username claim is something the identity
provider (or, for a self-asserted field like `preferred_username`, the
end user themselves) controls, not something DNS-shield can treat as
proof of who they are. Logging back into an account SSO itself
previously created works exactly as you'd expect, applying that
account's own role and permissions each time. The client secret is stored the same way the SMTP and threat-intel
API keys are - masked to a short preview once saved, and left untouched
if you save the form again without retyping it.

### HTTPS for the dashboard

`web.https_enabled` (Settings -> General, **on by default**) makes the
dashboard's own web port serve HTTPS instead of plain HTTP - this
replaces the port, it doesn't add a second one, so as long as it's on,
only `https://` reaches the dashboard on `web.listen_port` (the
[startup placeholder page](#startup) shown while the rest of the service
comes up serves HTTPS too, using the same certificate, so there's no
protocol mismatch during boot). Requires restarting the container to
take effect if you change it, same as the listen address/port
themselves.

With no certificate configured, DNS-shield generates its own self-signed
certificate the first time it starts with HTTPS on, and reuses that same
one on every later restart (`<data dir>/tls/cert.pem`/`key.pem` - part
of the data volume, so it survives a container recreate, and the private
key is written with `0600` permissions). Your browser will show a "not
trusted" warning the first time you connect, since a self-signed
certificate isn't backed by a certificate authority your browser already
trusts - the connection itself is genuinely encrypted either way, this
warning is only about identity verification, not encryption strength.
Click through it once, or - the actually correct fix if this matters to
you - set `web.https_cert_path`/`web.https_key_path` to a real
certificate and key pair instead (e.g. one an ACME client like
`certbot`/`lego` issues for a domain name that actually resolves to
this host, mounted into the container alongside the data volume).
DNS-shield never talks to an ACME provider itself - it only ever reads
whatever cert/key files you point it at, the same "no outbound calls you
didn't ask for" principle as everything else in this project. If you'd
rather skip the self-signed-certificate warning altogether on a
LAN-only deployment you're not worried about, turn `web.https_enabled`
back off in Settings -> General (or edit it in the config before first
boot) to go back to plain HTTP.

HTTPS also puts the `Secure` flag on the session cookie automatically
(see **Security notes** below) and adds a `Strict-Transport-Security`
header to every response. If `web.https_enabled` is off and the
dashboard is listening on anything other than loopback
(`web.listen_address` isn't `127.0.0.1`/`::1`), a startup log line calls
this out explicitly - login credentials and the session cookie are sent
unencrypted on the network as long as that's the case, whether you
turned HTTPS off yourself or are still running a config from before it
became the default. Turn `web.https_enabled` back on, or put a
TLS-terminating reverse proxy (the [built-in
one](#reverse-proxy-optional) works fine for this) in front of it.

**If you're running a config from before HTTPS became the default**,
Settings -> General shows a one-click **"Migrate to HTTPS now"** button
right below the HTTPS checkbox whenever it's currently off
(`POST /api/settings/web/migrate-https`, admin-only). It does exactly
what checking the box and saving would do - generates the self-signed
certificate immediately (skipped if you've already set your own
`web.https_cert_path`/`web.https_key_path`) and flips
`web.https_enabled` on - just packaged as a single action with a clear
label, so you don't need to go hunting for the right checkbox to adopt
the new default. A container restart is still required for it to
actually take effect, same as flipping the checkbox by hand; the button
disappears once HTTPS is on.

### DNS-over-HTTPS / DNS-over-TLS for clients

Everything above this point is about DNS-shield as a DoH/DoT *client*
talking to your upstream resolver. This section is the other direction:
DNS-shield itself answering DoH/DoT queries *from* your clients, on top
of the plain port-53 UDP/TCP it always listens on.

**DoH** needs no separate toggle - `POST /dns-query` and
`GET /dns-query?dns=<base64url>` (RFC 8484, raw DNS wire format in
`application/dns-message`) are always present on the same web port as
the dashboard, sharing its cache, DNSSEC cache, and blocklist state, so
a DoH query is filtered/blocked/logged exactly like a plain one. It's
only actually useful once `web.https_enabled` is on, though - DoH is
DNS-over-*HTTPS*, and most clients that support it (browsers' built-in
DoH settings, `curl --doh-url`, etc.) either require TLS outright or
won't send real traffic over plain HTTP.

**DoT** is off by default - `dns.dot_enabled` (Settings -> DNS, requires
a container restart) opens a second listener on `dns.dot_port` (853 by
default) speaking DNS-over-TLS (RFC 7858): the same length-prefixed
wire format as plain DNS-over-TCP, wrapped in TLS. It reuses whatever
certificate the dashboard's HTTPS setting resolves to - your own
`web.https_cert_path`/`web.https_key_path` if set, otherwise the same
auto-generated self-signed one described above. That matters more here
than for the dashboard: most OS-level DoT clients (Android's "Private
DNS", systemd-resolved, etc.) verify the certificate against a trusted
CA and simply refuse a self-signed one - there's no "click through the
warning" option like a browser gives you - so a self-signed certificate
makes DoT mostly untestable-but-present until you point it at a real
one.

Both listeners run only in the main process, not distributed across
`DNSSHIELD_DNS_WORKERS` worker processes the way plain UDP/TCP is - the
web dashboard itself is already single-process-only, and DoH/DoT follow
that same boundary rather than adding per-worker certificate loading and
`SO_REUSEPORT` interaction for a comparatively low-volume path. With the
shipped `docker-compose.yml`'s host networking, DoT is reachable as soon
as `dns.dot_enabled` is on - no port mapping needed. On bridge networking,
add a `- "853:853/tcp"` mapping (or whatever port you set) yourself,
matching the block page's own port-mapping pattern above.

### Prometheus metrics

`GET /metrics` (unauthenticated, same as the public dashboard summary)
exposes a small set of Prometheus counters and gauges in the standard
text exposition format: `dnsshield_queries_total` /
`dnsshield_blocked_total` (derived live from `stats.db`, so they read
correctly across every `DNSSHIELD_DNS_WORKERS` process sharing that
database, and Prometheus's own `rate()`/`increase()` handle a reset from
clearing the log or 30-day retention pruning the normal way - as a
counter reset, not a negative rate), `dnsshield_blocklist_domains` /
`dnsshield_allowlist_domains`, `dnsshield_cache_entries` /
`dnsshield_cache_hits_total` / `dnsshield_cache_misses_total` /
`dnsshield_cache_stale_hits_total`, `dnsshield_anomalies_unacknowledged`,
and `dnsshield_uptime_seconds`. The `dnsshield_dnssec_*_cached` and
`dnsshield_cache_*` families are the exception to the "aggregates across
workers" property above - both the DNSSEC cache and the DNS answer cache
are per-process, so with more than one `DNSSHIELD_DNS_WORKERS` these only
reflect whichever process the web UI happens to be (the same one that
owns `create_app`), not a sum across all of them.

A ready-made Grafana dashboard for these metrics ships in
`grafana/dnsshield-dashboard.json` - import it in Grafana (Dashboards ->
New -> Import, upload the JSON) against any Prometheus datasource
scraping `GET /metrics`.

### Startup

The dashboard's own port is bound as early as possible, before
blocklists, DHCP, the reverse proxy, or anything else finishes
initializing - visiting it right after `docker compose up` shows a small
auto-refreshing "DNS-shield is starting up..." page instead of a
connection error, until the real dashboard takes over that same port a
moment later. This placeholder page speaks whichever protocol the real
dashboard is about to (plain HTTP, or HTTPS with the same self-signed/
configured certificate once that's ready - see [HTTPS for the
dashboard](#https-for-the-dashboard) above), so there's no protocol
mismatch to work around while it's up. Blocking itself comes up even
faster than that (see **Blocklist formats and suggested lists** above
for the disk-cache warm start) - the placeholder page is purely about
the *web UI* not being ready yet, not about queries going unfiltered.

### Health check

`GET /healthz` (also unauthenticated) is a plain liveness check -
`{"status": "ok", "uptime_seconds": ...}` with a 200 status if the web
process is up and serving requests, nothing more (it doesn't touch
`stats.db`, the blocklist, or any other subsystem, so it can't itself
become slow or fail for reasons unrelated to "is this process alive").
The shipped image's own `HEALTHCHECK` already points `docker inspect
--format='{{.State.Health.Status}}'`/`docker ps` at it via
`app/healthcheck.py`, which tries plain HTTP first and falls back to
HTTPS (skipping certificate verification, since the target is always
`127.0.0.1` inside the same container) so it keeps working whichever
way `web.https_enabled` is set. Point an external uptime check or a
Kubernetes `livenessProbe` at the same path if you're running this
outside `docker compose`.

### Pause blocking

The bar at the top of the dashboard can pause *all* blocking network-wide
for a chosen duration (10/30/60/120 seconds, 5/10/30/60 minutes, or until
you manually resume it) - useful for quickly checking whether DNS-shield
is the cause of something breaking, without having to hunt down and
temporarily remove a specific denylist entry or blocklist. While paused,
every query resolves as if no blocklist, denylist, or client group
existed; it self-expires exactly at the chosen time (no polling/cleanup
needed - the timestamp is just checked against the current time) or you
can hit "Resume blocking" early. Only Administrator accounts can see or
use this bar - see **Multi-user accounts, roles, and the public view**
above.

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

### Dashboard language

The dashboard is available in eight languages - English, Polski,
Deutsch, Français, العربية, 中文, 日本語, and 한국어 (more of the UI is
translated over time; anything not yet translated just stays in
English). By default it follows your browser's own language
(`navigator.language`) - no setting needed. To pin one language for
your account regardless of which browser or device you sign in from, go
to Settings -> General -> "Dashboard language" and pick one instead of
"Automatic"; this is stored per-account (`users[].language` - one of
`en`/`pl`/`de`/`fr`/`ar`/`zh`/`ja`/`ko`, or unset for automatic) and
takes effect immediately, no reload needed. The public, signed-out view
and the login page (no account to look a preference up on yet) always
follow the browser's language. Each language's translation dictionary
is a JSON file under `app/locales/`, fetched from the same origin
(`GET /api/locales/{lang}`) the first time that language is selected -
nothing is sent to any third party to translate it. The language list
itself (`GET /api/languages`, backing that dropdown) and the
server-side validation of what you can save both come from one shared
list in the backend, so adding a whole new language later is exactly
two things: one entry in that list, one new locale JSON file - nothing
else in the UI needs to change to pick it up.

### Mobile

The dashboard is usable from a phone - checking or pausing blocking, or
adding a quick allow/deny rule, doesn't require a laptop. Below ~640px
wide: form fields and settings groups collapse to a single column, wide
data tables (query log, Stats breakdowns, allow/deny/blocked-client
lists) scroll horizontally within their own box instead of forcing the
whole page to, and long domains wrap instead of stretching their column.
There's no separate mobile app or API - it's the same page, same
`GET /`, just responsive CSS.

### Resetting config from a hand-edited YAML file

DNS-shield's live configuration lives in `./data/config.db`, not a YAML
file - there is no live file to edit, and nothing ever writes config
changes to one. Config is edited through the dashboard/REST API, and a full export is
written to `./data/config.backup.yaml` every 12 hours and at every startup
as a plain-text backup. That backup file is only ever *read* to seed a
fresh database (an empty data volume's first boot, or after you delete
`config.db` to reset). To hand-edit config as YAML: stop the container,
edit (or replace) `./data/config.backup.yaml`, delete `./data/config.db`
(and its `-wal`/`-shm` files, if present), and start it again.

### Downloading a backup

Settings -> General -> **Download backup (.zip)** gives you the same full
config snapshot as `data/config.backup.yaml` above, but as a file your
browser downloads to your own machine - built entirely in memory and sent
straight back, nothing written to disk on the server beyond what's already
in `config.db`. The zip has `config.yaml` (restore it the same way as
`config.backup.yaml` above, or see the dashboard restore below) plus a
`README.txt` spelling out both the fresh-instance and existing-instance
manual-restore cases.

Like `config.backup.yaml`, this is a full, unmasked snapshot - any
threat-intel API keys come out in plain text, and every user account's
bcrypt password hash comes out too (not reversible to the original
password, but still worth keeping private). Treat the downloaded file
like you would a password: back it up somewhere you'd store a password,
not somewhere public.

**Settings -> Import -> Restore from backup** applies one of these zips
without leaving the dashboard or touching the container - upload it and
your entire current configuration is replaced outright with whatever was
in the backup (no merging, since it's DNS-shield's own native format with
nothing to convert). Irreversible unless you've also backed up the config
you're about to overwrite - the dashboard asks for confirmation first.

## DHCP server (optional)

Settings -> DHCP has a built-in DHCPv4 server - entirely optional, off by
default, and implemented natively (no `dnsmasq`/`Kea` process bundled
in) so it's driven by the exact same `config.db` as everything else and
shows up in the exact same dashboard.

**This needs real access to your LAN's broadcast domain.** DHCP relies on
L2 broadcast, which a bridged Docker network doesn't forward - a
container behind NAT is isolated from it. The shipped `docker-compose.yml`
already uses `network_mode: host` (see
[Networking: host mode by default](#networking-host-mode-by-default)
below), so the broadcast domain itself isn't the blocker; DHCP just also
needs two extra capabilities to create/manage VLAN sub-interfaces and open
the raw sockets it needs on port 67:

```yaml
services:
  dns-shield:
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
```

These aren't in the compose file by default since they're only needed
once you actually turn DHCP on - add them, then `docker compose up -d`
to recreate the container with them. If you've switched back to bridge
networking (see the section below), DHCP can't reach your LAN at all in
that mode - keep it disabled and either run a real DHCP server on your
router as usual, or run DNS-shield's DHCP server on bare metal/a VM with
a real network interface instead of in a bridged container.

**Scopes** are the core unit of configuration - one per subnet/VLAN.
Each has: a name, the network interface to listen on, an optional
numeric VLAN ID (DNS-shield creates and manages the tagged 802.1q
sub-interface itself via netlink - no manual `ip link` setup needed),
this server's own IP address on that network (the DHCP "server
identifier"), the network in CIDR form, a pool range, and the usual
per-network settings: gateway, DNS servers (defaults to this box itself
if left blank - the whole point of pairing DHCP with DNS-shield), domain
name, lease time, NTP servers, WINS servers, interface MTU, a TFTP
server/boot filename pair for PXE network booting, static routes, and
IPs to exclude from the pool. Anything not covered by a named field -
any of the 100+ options the DHCP spec defines - goes in **custom DHCP
options**, one per line as `code:type:value` (`type` one of `ip`,
`ip_list`, `string`, `uint32`, `hex`), applied on top of everything
else.

**Static reservations** pin a specific MAC address to a specific IP
forever (never handed out to anyone else, never expires) and can
override that one client's DNS servers independently of the rest of the
scope - handy for a device that needs to keep resolving through a
different resolver. Add one by hand under a scope, or click **Reserve**
next to an existing entry in the **Active leases** table to turn a
dynamic lease permanent without retyping its MAC/IP.

Every request/response (DISCOVER/OFFER/REQUEST/ACK/NAK, RELEASE,
DECLINE, INFORM) is handled directly, one thread per scope. Leases
persist in their own local SQLite file, independent of `config.db`, and
expire and get swept automatically. Known limitations: IPv4 only, and no
DHCP relay-agent (`giaddr`) support - the server has to share an L2
segment with its clients (a relay agent forwarding from a remote subnet
won't work).

### Rogue DHCP server detection

A second, independent piece: Settings -> DHCP -> **Rogue DHCP server
detection** periodically broadcasts a real DHCPDISCOVER on the network
and listens for DHCPOFFER replies - from *any* DHCP server that happens
to answer, not just this one. Works even with DNS-shield's own DHCP
server switched off, purely as a network health check. Any responding
server IP that isn't on the allow-list (this box's own scope
server-identifier IPs are always implicitly allowed, plus whatever else
you list, e.g. your router) raises a **high**-severity alert - a sign of
a second, possibly rogue or simply misconfigured, DHCP server answering
on the same network, which is exactly the kind of thing that causes
random clients to get the wrong gateway/DNS with no obvious cause.

### New-client detection (DNS and DHCP)

Settings -> DHCP -> **New-client detection** has two independent
switches, one for DNS query clients and one for DHCP lease clients. Turn
either on and set a learning period in days; for that long, every client
it sees just gets quietly remembered, building up a baseline of "normal"
devices on your network. Once the learning period elapses, the first
time it ever sees a client it hasn't already learned raises a low
severity alert - "New DNS client detected" or "New DHCP client
detected" - once per client, never repeated for the same one again.

The learning period restarts automatically the moment you flip either
switch on, and the DNS side also restarts automatically whenever you
purge the query log (Settings -> Cleans -> **Delete all logged
queries**) - the log is your client history, so wiping it means starting
that history over. Both sides also have their own **Reset learning**
button for restarting on demand without needing to touch either
of those.

## Reverse proxy (optional)

Settings -> Reverse proxy manages a real `nginx` process from inside
DNS-shield - no separate container, no config file to hand-edit. Off by
default; the one global toggle at the top of the tab starts
`nginx -g "daemon off;"` as a child process, regenerates every domain's
config file from `config.db`, and restarts nginx automatically if it
ever crashes (a background monitor thread polls it every couple of
seconds).

**Ports 80 and 443 are not used at all by default.** With the shipped
`docker-compose.yml`'s `network_mode: host` (see
[Networking: host mode by default](#networking-host-mode-by-default)),
nginx binds directly to the host's ports when you turn this feature on -
there's no `docker-compose.yml` to edit and no container to re-create,
since there's no `ports:` list to keep in sync with what's enabled. Ports
80/443 simply stay free on the host for anything else running there as
long as you leave this feature off, which is also the default
(`proxy.enabled: false`). Flip the switch, and nginx starts listening on
80/443 within a few seconds - just make sure nothing else on the host is
already bound to those ports first.

If you've switched to [bridge networking](#networking-host-mode-by-default)
instead, you do need to publish the ports yourself once you turn this
feature on:

```yaml
services:
  dns-shield:
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
```

(and re-create the container - `docker compose up -d` - for the new
port mappings to take effect).

**Domains** are the core unit - one entry per set of hostnames sharing
the same nginx server block. Each has: one or more hostnames, an
ordered list of **rules** (each either a **proxy** rule - a path plus an
upstream target nginx forwards to, with an optional "WebSocket support"
checkbox that wires the `Upgrade`/`Connection` headers it needs - or a
**redirect** rule - a path plus a
target URL and HTTP status code), optional TLS (certificate/key file
paths, plus "force HTTPS" to also emit an HTTP->HTTPS redirect on port
80), and an admin-only **custom nginx config** field appended verbatim
into that domain's server block for anything the structured fields
don't cover. A **health check** button resolves each hostname (through
DNS-shield's own resolver, so it reflects whatever routing/rewrites are
configured) and does an HTTP(S) reachability check against every
rule's upstream/redirect target, reporting the domain reachable if any
one of them answers - so you can tell a broken domain apart from one
that's just not been visited yet. **Get certificate** issues or renews a
Let's Encrypt certificate with `certbot certonly --webroot`, using the
domain's own hostnames and the email address you provide - it needs the
domain reachable on port 80 for the ACME HTTP-01 challenge to succeed,
same as any other webroot-based certbot setup.

**Permissions** follow the same pattern as everywhere else in DNS-shield
(see **Multi-user accounts, roles, and the public view** below): a User
needs `can_manage_proxy` plus a matching entry in `allowed_domains` to
touch a given domain at all, and can never set its custom-config field
regardless.

**What this intentionally does *not* duplicate**, compared to the
standalone reverse-proxy project this feature's design was based on:

- **Its own JWT-based auth and setup-token bootstrap.** DNS-shield
  already has its own user accounts, sessions, roles, and per-permission
  access control (see **Multi-user accounts** below) - bolting on a
  second, independent auth system for just this one tab would be pure
  duplication with no benefit, and a second place for credentials to go
  stale or get out of sync.
- **Its own bundled mini-DNS-server for resolving proxied hostnames.**
  DNS-shield already *is* a full DNS server for every hostname on the
  network, not just the ones being proxied - pointing a proxied hostname
  at this box is just a normal DNS record (a rewrite, or your router's
  DHCP-assigned resolver), so a second, narrower DNS server bundled just
  for the proxy would be redundant and would only know about a subset of
  what the real one already handles.

**Port 80 collision warning.** DNS-shield's own local "blocked" page
(Settings -> DNS -> `block_page_port`, see **Local "blocked" page**
above) defaults to port 80. If you enable both the block page and the
reverse proxy on the same host, they'll fight over that port - move one
of them (`block_page_port` for the former, or don't map a domain's rules
to port 80 for the latter) before turning both on.

## Importing from AdGuard Home or Pi-hole

Both importers live in the dashboard's **Settings -> Import** tab (or as a
one-off command-line script), and both work the same way: read one file
from your existing setup, merge what's supported into DNS-shield's config,
and print a summary of exactly what was and wasn't carried over.

### AdGuard Home

Converts `AdGuardHome.yaml`: filter and whitelist-filter subscriptions,
`user_rules` (both block rules and `@@` exceptions), upstream resolvers
(`tls://`/`https://` converted to `dot://`/`doh://`), blocking mode, and
each `clients.persistent[].ids` entry (IPs, CIDRs, and MAC addresses,
converted to a `mac:` pattern - AdGuard's own client-ID strings aren't a
concept DNS-shield has, those are skipped with a warning) as a
`client_groups` entry. AdGuard's listen address/port are deliberately
*not* imported - changing those here could stop matching your
docker-compose port mapping, so DNS-shield always keeps its own.

**From the dashboard**: upload the file, it's merged directly into the
running config and takes effect immediately - blocklists refresh right
away. This **replaces** your current blocklists, client groups, blocking
mode, and upstreams with AdGuard's, but keeps everything else - your
listen address/port, your web login, and anything else not listed above.

**From the command line**, for a fresh setup or to produce a file to review
before applying:

```bash
docker compose exec dns-shield python -m app.import_adguard /path/to/AdGuardHome.yaml
```

Not imported: listen address/port (see above), parental control/safe
browsing, DHCP, TLS termination, and your web UI password - AdGuard
stores a bcrypt hash that can't be turned back into plaintext, so set
that yourself from the dashboard.

### Pi-hole

Converts `gravity.db` - Pi-hole's own SQLite database, included in a
"Teleporter" backup or copyable directly from `/etc/pihole/gravity.db` on
the Pi-hole host: `adlist` (blocklist, and on newer schemas allow-list,
subscription URLs, enabled state preserved), enabled `domainlist` exact
allow/deny entries, enabled `domainlist` regex-deny entries (mapped to
DNS-shield's own [experimental regex denylist](#regex-denylist-experimental),
which gets turned on for you), and `client` IPs as `client_groups`.

**From the dashboard**: upload `gravity.db`, same merge-and-apply-immediately
behavior as the AdGuard Home import above.

**From the command line**:

```bash
docker compose exec dns-shield python -m app.import_pihole /path/to/gravity.db
```

Not imported: upstream DNS servers, listen address/port, and blocking mode
(these live in Pi-hole's `setupVars.conf`/`pihole.toml`/dnsmasq config, a
different file this importer never reads), regex ALLOW entries (DNS-shield
has no regex allowlist, only a regex denylist), per-client/per-group list
assignments (gravity.db's group-membership tables vary across Pi-hole
versions, so an imported client gets DNS-shield's default global policy,
not whichever Pi-hole group it belonged to), and your web UI password.

## Architecture

```
app/
  config.py          config storage: SQLite (data/config.db) as the live source of
                      truth, exported to data/config.backup.yaml every 12h
  netmatch.py         shared IP/CIDR matching for client groups and log-ignore rules
  blocklist.py        fetches + parses hosts/AdBlock/plain-domain lists (auto-detecting
                       each source's format) for block, allow, and alert-rule watch lists,
                       refreshes on a timer, caches lists to disk for offline restarts, and
                       (experimental) matches an in-memory cache of compiled regex denylist
                       patterns
  blocklist_catalog.py  fixed list of well-known public blocklists offered as one-click
                       "Suggested lists" in the dashboard's Blocklists section
  dns_server.py        dnslib-based UDP/TCP DNS server (plus an optional DoT listener);
                        blocks locally, answers a custom record, serves a cached answer,
                        or forwards to your upstreams
  metrics.py            renders the Prometheus text-exposition format for GET /metrics
                        (see above) from the same stats.db/blocklist/cache/anomaly state
                        everything else already reads
  healthcheck.py         standalone script backing the Docker image's HEALTHCHECK - hits
                        GET /healthz over HTTP then HTTPS, whichever the running config uses
  audit.py               who-changed-what log: SQLite storage (data/audit.db), fed by a
                        single piece of middleware in web/server.py that covers every
                        mutating /api/ endpoint automatically (see above)
  two_factor.py           TOTP secret/QR generation and verification (pyotp + qrcode),
                        plus the short-lived pending-login-token store the two-step
                        login flow uses (see Two-factor authentication above)
  passkeys.py             WebAuthn registration/authentication ceremonies (see Passkeys
                        above), thin wrapper over the webauthn library
  sso.py                  OpenID Connect discovery, authorization-code exchange, and ID
                        token verification (see Single sign-on above), built on Authlib + joserfc
  dns_rewrites.py       custom local A/AAAA record matching (see Custom DNS records above)
  dns_cache.py         in-memory, TTL-respecting cache of upstream answers (LRU-bounded,
                       nothing persisted to disk)
  block_page.py         optional local HTTP server for the "blocked" page (see above) -
                        only ever answers requests that already arrived at it
  upstream.py          upstream transports: plain UDP/TCP, DNS-over-TLS, DNS-over-HTTPS
  upstream_stats.py    rolling latency/success tracking + background health probing,
                       backing the fastest/most_stable upstream selection strategies
  client_names.py      background reverse-DNS (PTR) resolver for dashboard display only
  stats.py             query log storage: SQLite database (data/stats.db), async writes,
                       hourly pruning, filterable search for the query-log browser
  import_adguard.py    one-off AdGuard Home -> DNS-shield config converter (see above)
  import_pihole.py      one-off Pi-hole gravity.db -> DNS-shield config converter (see above)
  enrichment.py         VirusTotal/AbuseIPDB/OTX/GreyNoise/Shodan/URLhaus/RDAP/crt.sh reputation
                        lookups, called either from the "Enrich" button's endpoint or from
                        auto_enrich.py below (see above)
  whois.py              legacy WHOIS (port 43) client with IANA-referral server discovery,
                        used as enrichment.py's fallback when a domain's RDAP lookup fails
  enrichment_store.py   local storage for enrichment results: SQLite (data/enrichment.db)
  auto_enrich.py         background worker that runs Enrich once for each newly-seen queried
                        domain when enabled (see Automatically enriching newly-seen domains
                        above) - watches the query log the same way anomaly.py's
                        watched-domain loop does
  anomaly.py             local, heuristic anomaly detection over the query log, plus the
                        watched-domain/alert-rules background loop - SQLite storage
                        (data/anomalies.db) (see above)
  notifications.py       optional email for new anomalies, straight to the SMTP server you
                        configure (stdlib smtplib only) - never called on its own (see above)
  auth.py               bcrypt password hashing (thin wrapper, isolates the bcrypt
                        dependency to one module)
  users.py              multi-user accounts + roles/permissions: SQLite-backed (via
                        config.py's `users` list), migrates a pre-multi-user
                        web.username/web.password into a bcrypt-hashed admin account
  sessions.py           in-memory login sessions (token -> username) backing the
                        session cookie - never persisted to disk, a restart signs
                        everyone out
  web/server.py        FastAPI REST API + session-cookie auth/RBAC, backing the dashboard
  web/static/          single self-contained dashboard page, plus a separate login
                       page (no external assets/CDN - even the favicon/logo is an
                       inlined SVG, not a fetched file)
  main.py              wires the above together and starts everything
```

Request flow: client -> DNS-shield (UDP/TCP :53) -> blocklist match? ->
NXDOMAIN/null-IP locally; otherwise a custom DNS record match? -> answer
locally; otherwise cache hit? -> answer from the local cache; otherwise
forward the raw packet to an upstream resolver, relay the raw reply back,
and cache it for its remaining TTL. Every query is recorded to the local
stats log regardless of how it was answered.

### Concurrency

By default DNS-shield runs as a single process. Within that process, the
DNS server handles each incoming query on its own thread (dnslib's
`ThreadingMixIn` UDP/TCP servers) - there's no fixed connection limit, and
since resolving is I/O-bound (waiting on the upstream socket, or on the
in-memory cache/blocklist lookup) this comfortably handles the query bursts
of a home or small-office network. Threads don't give real parallelism
across CPU cores for the Python code itself (the GIL), but since the work
here is I/O-bound rather than CPU-bound, that rarely matters in practice.
The web UI runs the same way - FastAPI/Starlette dispatches each request
to a thread pool, all within that one process.

For higher query throughput than one process comfortably handles, set
`DNSSHIELD_DNS_WORKERS` (an environment variable, like `DNSSHIELD_DATA_DIR`
- not a dashboard setting) to a number greater than 1. DNS-shield forks
that many additional, fully independent DNS-serving processes - each with
its own blocklist/cache/upstream-health state - and binds all of them to
the same DNS port with `SO_REUSEPORT`, so the kernel load-balances incoming
queries across every process/core. Only the original process runs the web
UI, anomaly detection, and notifications - those stay single-process
regardless of this setting, so login sessions and anomaly alerts are never
duplicated. The extra DNS-only processes reload their config from
`config.db` every few seconds (so a change from the dashboard reaches them
quickly without a restart) and independently fetch their own copy of every
configured blocklist/watch-list/malicious-IP list on the normal refresh
schedule - correct and simple, at the cost of each worker doing that fetch
work separately rather than sharing one result. The query log
(`stats.db`) is safe to write from multiple processes at once (SQLite's
WAL mode, already the default here). `SO_REUSEPORT` is Linux/BSD-only; on
a platform without it, DNS-shield logs a warning and falls back to a
single worker. This is all still not tuned for very high sustained
throughput regardless of worker count: each forwarded query opens a fresh
UDP socket to the upstream (no connection reuse/pooling). The cache above
absorbs most of the repeat traffic that would otherwise hit the upstream
resolver.

**Memory**: every blocklist (global, per-group, allow-list, alert-rule,
malicious-answer-IP) is held fully in memory as a `frozenset[str]` once
refreshed, which is what makes matching an O(1) set lookup instead of a
per-query network or disk read. Measured directly against real feeds: a
combination of StevenBlack's Unified Hosts plus three large HaGeZi lists
(~867k unique domains total) costs about **196MB**; the
[Newly Registered Domains](#newly-registered-domains-nrd) list alone is
~2.8M domains and costs about **650MB** - roughly 200-230 bytes per
domain either way, consistent across both measurements. Multiple DNS
workers (above) each hold an independent copy, so the same set of
subscribed lists costs proportionally more RAM per worker, not once
shared across them.

## Development

A pytest suite covers the pure-logic modules (typosquat detection, IP/CIDR/MAC/host
matching, blocklist format parsing, threat-intel error handling, and the
anomaly-detector false-positive exclusions), using the real `ConfigStore` against a
throwaway SQLite file rather than hand-rolled fakes wherever practical.

```bash
pip install -r requirements-dev.txt
pytest
```

## Security notes

- Change the default `admin` password before exposing the dashboard
  beyond localhost (Settings -> General -> "Your account", or Settings ->
  Users). Passwords are always bcrypt-hashed - see **Multi-user accounts,
  roles, and the public view** above.
- The DNS resolver itself is also guarded by default - see [Query access
  control](#query-access-control-recursion-acl) above - so it can't be
  used as an open resolver/DNS-amplification reflector just because
  `dns.listen_address` has to be reachable from your LAN.
- The entire data directory (`./data` on the host, `/data` in the
  container - `config.db`, `config.backup.yaml`, `stats.db`, TLS keys,
  everything) is created with `0700` permissions on startup, so only the
  user the container runs as (root inside the container's own namespace,
  by default) can read any of it - no other local account on the host can
  traverse into it or open a file inside, regardless of that file's own
  permission bits.
- `GET /openapi.json` (and `/docs`/`/redoc`) are disabled - the API schema,
  including every settings field name (secret ones like `smtp_password`
  or `sso.client_secret` included, values never included), isn't exposed
  to an unauthenticated caller doing reconnaissance.
- Every response carries a baseline set of security headers
  (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`, and a `Content-Security-Policy` that
  restricts script/style/image/frame/object sources to the dashboard's
  own origin) plus `Strict-Transport-Security` once a request actually
  arrives over HTTPS. The CSP still allows inline `<script>`/`<style>` -
  the dashboard is a single self-contained page with no external
  resources - so it isn't a full defense against XSS by itself, but it
  does block a large class of exfiltration/clickjacking payloads that
  rely on loading something from outside the page's own origin.
- The login endpoint is rate-limited per source IP (`web.login_max_attempts`,
  default 5 failures before a `web.login_lockout_minutes`-long, default
  15, lockout - a correct password doesn't bypass an active lockout).
  Nothing else on the API is rate-limited, though; put the dashboard
  behind your own reverse proxy / VPN if you're exposing more of it
  outside your LAN than the login form. The session cookie gets the
  `Secure` flag automatically once `web.https_enabled` is on (see
  [HTTPS for the dashboard](#https-for-the-dashboard) below, on by
  default) - if you've turned HTTPS back off for a plain-HTTP LAN
  deployment, that flag comes off too, since the browser would otherwise
  never send the cookie back at all.
- API tokens (`Authorization: Bearer <token>`, see **API tokens** above)
  are deliberately not rate-limited the way the login endpoint is - a
  256-bit random value makes guessing infeasible regardless, unlike a
  human-chosen password. A token is a bearer credential: anyone holding
  it can use it, indistinguishably from the account that created it, for
  as long as it stays valid - treat it like a password, and revoke it the
  moment you suspect it leaked.
- The public, signed-out view (`/` and `GET /api/public/summary`) is
  intentionally reachable without a login - it only ever returns the
  query trend and top blocked domains, nothing client- or domain-specific
  beyond that.
- Port 53 needs root or `CAP_NET_BIND_SERVICE` in the container - the
  provided image runs as root by default for this (same approach as the
  official AdGuard Home / Pi-hole images). For a fully rootless setup
  instead, the image already ships a dedicated `dnsshield` user and an
  entrypoint that, once told to, `chown`s the mounted volumes and then
  drops from root to that user via `gosu` before starting the app - opt
  into it with a compose override:

  ```yaml
  services:
    dns-shield:
      environment:
        - DNSSHIELD_RUN_AS_NONROOT=1
      cap_drop:
        - ALL
      cap_add:
        - NET_BIND_SERVICE
        - CHOWN
        - SETUID
        - SETGID
        - DAC_OVERRIDE
      read_only: true
      tmpfs:
        - /tmp
        - /run
        - /var/lib/nginx
        - /var/log/nginx
        - /var/lib/letsencrypt
        - /var/log/letsencrypt
  ```

  Add `NET_ADMIN` and `NET_RAW` to `cap_add` too if you're also turning
  DHCP on (see [DHCP server (optional)](#dhcp-server-optional) above -
  it needs those two regardless of root/rootless). `nginx/nginx.conf`'s
  own `user root;` directive is silently ignored once the master process
  isn't actually root - harmless, not an error, nothing to change there.
- The shipped `docker-compose.yml` sets `no-new-privileges` so nothing
  inside the container can ever gain more privileges than it started
  with. There's deliberately no `mem_limit`/`pids_limit` baked in as a
  default: a wrong guess on either fails badly in a way that's easy to
  mistake for something else entirely - too-low RAM doesn't make the
  container exit with an error, it makes everything crawl under memory
  pressure while looking exactly like a hang (see the note on blocklist
  memory use just below), which is a far worse failure mode to ship a
  guessed number for than simply leaving it uncapped. Add your own
  `mem_limit`/`pids_limit` to a compose override if you specifically want
  a ceiling to catch a genuine runaway (a bug, a fork bomb) - just size
  it to your own setup rather than copying a number from here.
  **All blocklist/allow-list/watch-list sources are held in memory at
  once** (as both a merged set and a per-domain source-attribution map,
  so the actual footprint is a multiple of the raw list size), and a
  handful of large third-party lists (HaGeZi's Multi PRO, for instance,
  is itself in the hundreds of thousands of domains) can add up to more
  than you'd expect from the download size alone - each additional
  client group with its own extra blocklist sources adds again on top.
  If the container is slow to start or feels sluggish with a rich
  blocklist setup, check `docker stats <container>` before assuming
  something's actually stuck: memory usage sitting close to a limit
  you've set yourself (and heavy disk I/O alongside it, from the kernel
  reclaiming/swapping pages) looks a lot like a hang but is really just
  the container being starved - raise the limit rather than waiting it
  out.
- Threat-intel API keys (VirusTotal/AbuseIPDB/OTX/GreyNoise/Shodan/URLhaus/your own local service),
  the SSO client secret, and the SMTP password are stored in
  `config.db`/`config.backup.yaml` like any other setting - anyone with
  access to the web UI or `./data` volume can read or use them. The
  Settings page and `GET /api/settings` never echo a key back, only
  whether one is set (and a masked first/last-character preview). Each of
  these fields has its own **Clear** button next to it, so retiring a key
  (rotated, revoked, no longer needed) doesn't require pasting in a
  throwaway value to overwrite it - saving a field's form with it left
  blank always keeps whatever is already stored, by design, which is what
  makes an explicit way to actually remove one necessary. `local_url` is
  stored and shown in plain text (it's a URL, not a secret) - don't put
  credentials in it, use the separate local API key field for that.
- Fetching a blocklist/allow-list/watch-list source URL, a notification
  webhook (Discord/Slack), or the URL-ping target rejects a hostname
  that resolves to a private, loopback, link-local, or otherwise
  non-public address (SSRF protection), re-checked at the moment of the
  actual connection (not just the upfront validation) so a DNS answer
  that changes between the two can't slip a private address past the
  check - see [Blocklist formats and suggested
  lists](#blocklist-formats-and-suggested-lists) above. A pattern added
  to the regex denylist (dashboard, API, or Pi-hole import) that shows
  signs of catastrophic backtracking is rejected before it's saved, and
  matching against live queries is time-boxed regardless - see [Regex
  denylist](#regex-denylist-experimental) above.
- Dependencies are kept on current, CVE-patched versions across the board
  and bumped as new releases/CVEs land against whatever's pinned in
  `requirements.txt`.
- Every place a secret is checked against a stored value (API tokens,
  2FA backup codes) uses a constant-time comparison, so a network
  attacker can't use response-timing differences to guess a valid value
  one byte at a time. The dashboard login does the equivalent for
  usernames: a login attempt for a username that doesn't exist still
  runs a full (dummy) password hash check, so the response-time
  difference between "wrong password" and "no such user" can't be used
  to enumerate valid accounts.
- An SSO login can only ever authenticate an account that was itself
  created through SSO - if the identity your provider returns happens
  to match a local, password-based account (including the built-in
  `admin` account), the login is rejected rather than silently signed
  into that account. See [Single sign-on](#single-sign-on-sso--openid-connect)
  above.
- `enrichment.public_enabled` (Settings -> Threat intelligence -> "Enable
  public lookups") is off by default and is the actual gate on whether
  VirusTotal/AbuseIPDB/OTX are ever contacted - saving a key for one of
  them does not turn this on by itself. Anyone with dashboard access can
  flip it, same as any other setting.

## Limitations / roadmap

- No DoQ (DoH/DoT are supported both as an upstream transport and as a
  listener for clients - see above). [Parental
  control](#parental-control--safesearch) is limited to what DNS
  resolution can actually do - forced SafeSearch, per-group category
  blocklists, and per-group bedtime schedules - not per-app limits or
  content inspection.
- Client groups and `blocked_clients` also match by MAC address or resolved
  hostname (`mac:`/`host:` patterns, see above); MAC matching additionally
  depends on the host's ARP table being visible to the container, which
  the shipped `docker-compose.yml`'s host networking already provides (see
  [Networking: host mode by default](#networking-host-mode-by-default)) -
  it won't work if you've switched to bridge networking instead. Hostname
  matching depends on client name resolution being enabled
  (`dns.resolve_client_names`), which is off by default.
- HTTPS for the dashboard (see above) is self-signed by default - a
  browser-trusted certificate still means either providing your own or
  putting a reverse proxy with its own ACME client in front of it.
- Blocklist matching is domain/subdomain based. `||domain^` block rules and
  `@@||domain^` exception rules (both from subscribed lists and a group's
  own extra sources) are understood; a domain covered by an exception is
  never blocked by that same source, even if a broader rule in it would
  otherwise match. Everything else in the AdBlock/uBlock grammar is
  architecturally out of reach for a DNS-level blocker and is silently
  skipped rather than misinterpreted: element hiding (`##`/`#@#`) needs a
  browser to inject CSS into a page DNS-shield never sees, and per-request
  modifiers like `$third-party`, `$domain=`, or `$script` need the
  referring page and resource type, neither of which a DNS query carries -
  a domain rule with one of those modifiers is still enforced as an
  unconditional block, the same tradeoff Pi-hole and AdGuard Home make. A
  separate, experimental regex denylist exists for pattern-based blocking
  (see above), but it's a flat list of your own patterns, not an
  AdBlock-rule interpreter.

## License

BSD 3-Clause with the [Commons Clause](https://commonsclause.com/) condition - see [LICENSE](LICENSE). Free to use, modify, and redistribute; you may not sell it or charge a fee (hosting, consulting, support) for a product or service whose value comes substantially from this software.
