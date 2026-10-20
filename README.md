# Graylog Log Lab — Centralized Log Analysis for Incident Triage


> **Note on sources:** This lab recreates a deployment I administered in a professional role. Company names, hostnames, IP addresses, keys, and tenant identifiers have been sanitized or replaced with placeholders for confidentiality.

A working Graylog stack (server + OpenSearch + MongoDB) fed by a synthetic
event generator, built for hands-on incident-triage practice: auth failures,
VPN handshake health, DNS activity, and Windows logon events — the exact
log mix an L2/L3 support engineer reads when a ticket lands.

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
| `docker-compose.yml` | Graylog + OpenSearch + MongoDB lab stack (ports 9000, 514/udp, 12201) |
| `.env.example` | Copy to `.env`; how to generate the two Graylog secrets (placeholders only) |
| `scripts/generate_logs.py` | Stdlib-only synthetic syslog generator (UDP), incl. `--scenario` incident modes |
| `docs/architecture.md` | Design decisions: component roles, inputs, streams/index strategy, retention, hardening |
| `docs/search-queries.md` | Sample triage searches (brute force, VPN-down verification, DNS hunts, …) |
| `docs/dashboard-layout.md` | "First five minutes" triage dashboard: widgets, layout grid, workflow |
| `docs/interview-answers.md` | "How do you use logs in incident triage?" — talking points for interviews |
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
#    Syslog UDP input on port 514 — the generator speaks to it.

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
  all users/hosts are invented lab fixtures. Nothing here describes a real
  system.
- Secrets live in `.env` (git-ignored), never in the repo. The compose file
  ships unusable `<generate-your-own>` placeholders on purpose.
- **LAB ONLY:** OpenSearch's security plugin is disabled and Graylog's
  inputs are unauthenticated — acceptable on loopback, never on a network.
  Do not expose ports 514/9000/12201 to the internet. See the hardening
  notes in `docs/architecture.md` for what to change on a real host.

## Validation

What was actually verified in the build environment:

- **Generator:** `python3 -m py_compile` clean; every emitted line validated
  against an RFC 3164 regex — 300 mixed events, 0 malformed (all five event
  types, all three source hosts). Scenario runs asserted programmatically:
  `bruteforce` produced 30 failures from 198.51.100.23 + exactly 1
  success-after-failures; `vpn-flap` produced 12 PEER-B handshake-failure
  lines.
- **Compose:** `docker-compose.yml` parsed with `yaml.safe_load` and
  asserted: exactly the three expected services, Graylog ports 9000 /
  514/udp / 12201+12201/udp present, OpenSearch lab flags
  (`discovery.type=single-node`, `plugins.security.disabled=true`) set, and
  both Graylog secret fields contain only `<generate-your-own>` placeholders.
- **Not validated here:** live UDP transmission — this sandbox blocks
  outbound `sendto()` at the OS level (EPERM even on loopback), so the
  generator was validated via `--dry-run` output instead of a local UDP
  capture. On a real host, point it at the Graylog syslog input and verify
  messages arrive in the web UI's search view.
- **Full stack bring-up was not tested here** — `docker compose up` needs a
  real host with Docker and ~4 GB free RAM (plus `vm.max_map_count=262144`
  for OpenSearch). The generator scenarios are what make the stack useful
  once it's up.
