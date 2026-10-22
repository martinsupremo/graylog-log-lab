# Graylog Log Implementation — Centralized Log Analysis for Incident Triage

In support work, a ticket comes in and the answer is usually in the logs. This repo
is a Graylog stack (server, OpenSearch, MongoDB) fed by a small event generator, so
I can practice triage on auth failures, VPN handshakes, DNS activity, and Windows
logon events. All hosts and addresses are made up.

**What this demonstrates:** centralized log ingestion (Syslog UDP / GELF),
search-based triage with Lucene queries, the "narrow then widen" incident
workflow, brute-force detection (failures grouped by source IP, success after
failures = possible compromise), VPN handshake troubleshooting from kernel
logs, and designing a dashboard around the first five minutes of an incident.

```
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │ vpnserver    │  │ dnsserver    │  │ win-collector│
   │ sshd / sudo  │  │ dnsmasq      │  │ MSWinEventLog│
   │ kernel (wg0) │  └──────────────┘  └──────────────┘
   └──────┬───────┘
          │  syslog UDP 514  (or GELF 12201 for structured apps)
          ▼
   ┌──────────────────────────────────────────────┐
   │            GRAYLOG INPUTS                    │
   └──────────────────────┬───────────────────────┘
                          ▼
   ┌──────────────────────────────────────────────┐
   │      GRAYLOG SERVER :9000                    │
   │  routing → streams (auth / network)          │
   │  search, dashboards, alerts                  │
   └──────┬───────────────────────┬───────────────┘
          │ index                 │ config
          ▼                       ▼
   ┌──────────────┐       ┌──────────────┐
   │  OPENSEARCH  │       │   MONGODB    │
   │  log indices │       │ users, inputs│
   │  (the data)  │       │ streams, UI  │
   └──────────────┘       └──────────────┘
```

## Repo layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Graylog + OpenSearch + MongoDB implementation stack (9000 on loopback, 514/udp→1514, 12201) |
| `.env.example` | Copy to `.env`; how to generate the two Graylog secrets (placeholders only) |
| `scripts/generate_logs.py` | Stdlib-only synthetic syslog generator (UDP), incl. `--scenario` incident modes |
| `docs/architecture.md` | Design decisions: component roles, inputs, streams/index strategy, retention, hardening |
| `docs/search-queries.md` | Sample triage searches (brute force, VPN-down verification, DNS hunts, …) |
| `docs/dashboard-layout.md` | "First five minutes" triage dashboard: widgets, layout grid, workflow |
| `.gitignore` | `.env`, logs, `__pycache__` — secrets and noise never committed |

## Quick start

```bash
# 1. Set secrets (placeholders won't start the server)
cp .env.example .env
pwgen -N 1 -s 96                      # -> GRAYLOG_PASSWORD_SECRET
echo -n "your-admin-password" | sha256sum   # -> GRAYLOG_ROOT_PASSWORD_SHA2

# 2. Start the stack (needs a host with Docker and ~4GB RAM)
docker compose up -d
#    then: sudo sysctl -w vm.max_map_count=262144   (OpenSearch requirement)

# 3. Open Graylog at http://127.0.0.1:9000/ (user: admin) and create a
#    Syslog UDP input on port 1514 (container-side; the host forwards
#    514→1514 because Graylog runs non-root and can't bind 514).
#    The generator sends to host port 514 as usual.

# 4. Feed it logs
python3 scripts/generate_logs.py --count 100 --rate 50

# 5. Rehearse incidents
python3 scripts/generate_logs.py --scenario bruteforce --count 31
python3 scripts/generate_logs.py --scenario vpn-flap   --count 20

# 6. Try the searches in docs/search-queries.md and lay out the board in
#    docs/dashboard-layout.md.
```

## Security notes

- All IPs are RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24);
  all users/hosts are invented fixtures. Nothing here describes a real
  system.
- Secrets live in `.env` (git-ignored), never in the repo. The compose file
  ships unusable `<generate-your-own>` placeholders on purpose.
- **NOT FOR PRODUCTION:** OpenSearch's security plugin is disabled and Graylog's
  inputs are unauthenticated — acceptable on loopback, never on a network.
  Do not expose ports 514/9000/12201 to the internet. See the hardening
  notes in `docs/architecture.md` for what to change on a real host.

## Checks

- **Event generator:** compiles cleanly, and every line it produces matches the
  RFC 3164 syslog format (300 mixed events, 0 malformed). The `bruteforce`
  scenario produces 30 failed logins from 198.51.100.23 followed by one
  success, and `vpn-flap` produces 12 handshake failures.
- **Compose file:** defines exactly the three expected services, binds the web
  UI to 127.0.0.1:9000, maps syslog 514 to 1514/udp plus GELF on 12201/udp, and
  leaves both Graylog secrets as `<generate-your-own>` placeholders.
- **Next step:** start the stack on a host with Docker and about 4 GB of free
  RAM (OpenSearch also needs `vm.max_map_count=262144`), point the generator at
  the syslog input, and confirm the events show up in Graylog's search view.
  Until then, the generator's `--dry-run` mode shows exactly what it would send.
