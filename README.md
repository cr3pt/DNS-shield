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
  bind-mounted `./data` volume as plain YAML/JSON files. Nothing is sent
  anywhere else, and you can `grep` it yourself to verify.
- Small enough (~600 lines of Python) to actually read end to end; see
  [Architecture](#architecture) below for exactly what each file does.

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

On first start it seeds `./data/config.yaml` from
`config/config.example.yaml`. Open `http://<host>:3000`, log in with the
default `admin` / `changeme` credentials from that file, **change the
password**, and point a device's DNS at `<host>:53` to test it.

To use it network-wide, set it as the DNS server in your router's DHCP
settings (or on individual devices).

## Configuration

Everything lives in `./data/config.yaml` (bind-mounted, so it survives
rebuilds) and can also be edited live from the web UI:

```yaml
dns:
  listen_address: "0.0.0.0"
  listen_port: 53
  upstreams: ["1.1.1.1:53", "9.9.9.9:53"]   # only servers DNS-shield forwards to
  block_mode: "nxdomain"                     # or "null_ip"

blocklists:
  refresh_interval_hours: 24
  sources:
    - name: "StevenBlack Unified Hosts"
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      enabled: true

allowlist: []   # always resolved normally, even if a blocklist matches
denylist: []    # always blocked, even if not on a blocklist

web:
  listen_port: 3000
  username: "admin"
  password: "changeme"   # change this
```

Add/remove blocklists and allow/deny entries either by editing this file or
through the web UI (both write to the same file).

## Architecture

```
app/
  config.py       thread-safe YAML config store, mutated in place by the web UI
  blocklist.py    fetches + parses hosts/AdBlock-syntax lists, builds the block set,
                  refreshes on a timer, caches lists to disk for offline restarts
  dns_server.py   dnslib-based UDP/TCP DNS server; blocks locally or forwards the
                  raw request packet to your configured upstream resolvers
  stats.py        in-memory counters + bounded query log, snapshotted to disk
  web/server.py   FastAPI REST API + basic-auth, backing the dashboard
  web/static/     single self-contained dashboard page (no external assets/CDN)
  main.py         wires the above together and starts everything
```

Request flow: client -> DNS-shield (UDP/TCP :53) -> blocklist match? ->
NXDOMAIN/null-IP locally, or forward raw packet to an upstream resolver and
relay the raw reply back. Every query is recorded to the local stats log.

## Security notes

- Change the default web UI password before exposing it beyond localhost.
- The web UI has no rate limiting; put it behind your own reverse proxy /
  VPN if you expose it outside your LAN.
- Port 53 needs root or `CAP_NET_BIND_SERVICE` in the container - the
  provided image runs as root for this (same approach as the official
  AdGuard Home / Pi-hole images). Run rootless via a compose override with
  `cap_add: [NET_BIND_SERVICE]` and a non-root `user:` if you need that.

## Limitations / roadmap

- No DHCP server, no DoH/DoT/DoQ listener, no client-specific policies yet.
- No built-in HTTPS for the web UI - put a reverse proxy in front of it if
  you need TLS.
- Blocklist matching is domain/subdomain based; it doesn't parse the full
  AdBlock rule grammar (element hiding, exceptions, regex rules).
