# Architecture & Design Decisions

## Components — what each container actually does

Graylog is three services, and knowing which one does what is what makes it
troubleshootable:

- **Graylog server** — the brain. Receives messages on its inputs, runs them
  through extractors/pipelines, serves the web UI and REST API on port 9000,
  and handles search by translating queries and fanning them out to the
  indexer. It does **not** store log data itself.
- **OpenSearch** — the indexer/storage. Every message lands in an index here;
  searches are really OpenSearch queries underneath. Disk sizing, index
  rotation, and retention are all ultimately about this component.
- **MongoDB** — the config database. Users, roles, inputs, streams,
  dashboards, and alert definitions live here — small, precious data. Back up
  MongoDB and you can rebuild the Graylog configuration; lose the OpenSearch
  volumes and you lose the logs themselves.

## Inputs

- **Syslog UDP 514** — the workhorse for network gear, Linux servers, and
  this implementation's generator (`scripts/generate_logs.py`). Host-facing
  port is 514; inside the container Graylog listens on 1514 (mapped
  `514:1514/udp`) because the Graylog process runs non-root and cannot bind
  privileged ports. UDP is fire-and-forget:
  no delivery guarantee, so it's fine here and common in production,
  but anything compliance-critical should ride TCP or a forwarder with a
  disk buffer (rsyslog omfwd, Graylog Forwarder, Filebeat).
- **GELF 12201 (TCP/UDP)** — Graylog's native format. Structured from the
  start: fields arrive already parsed instead of being regexed out of a flat
  string, and TCP gives you delivery confirmation. Prefer GELF (or Beats)
  for applications you control; syslog for everything that only speaks
  syslog.

One input per concern, bound deliberately: inputs are global or per-node,
and a misconfigured "catch-everything" input makes stream routing and
troubleshooting harder than it needs to be.

## Streams & index strategy

- **Streams** route messages by rule (source host, application, facility)
  into index sets — e.g. an `auth` stream for sshd/sudo/Windows logon events,
  a `network` stream for VPN and DNS. Streams are also the unit you hang
  permissions and alerts on: helpdesk sees auth + network, not everything.
- **Index sets** rotate on size or time (e.g. rotate at 1 GB or 1 day,
  whichever first). Rotation is what makes retention enforceable: deleting
  whole old indices is cheap; deleting individual old messages is not.
- **Retention thinking:** keep hot, searchable data for the window you
  actually triage in (30–90 days is typical for a small shop), archive or
  drop beyond that. Retention is a disk-budget decision first and a
  compliance decision second — an indexer that fills its disk stops
  indexing *everything*, which is an outage, not a cleanup task.

## Why Graylog (vs ELK / Splunk) at small scale

- **ELK/OpenSearch alone** is more flexible but you build the product
  yourself: ingestion, parsing, users/RBAC, alerting, dashboards. Graylog is
  that stack pre-assembled on top of the same indexer.
- **Splunk** is excellent and priced like it — ingestion-based licensing
  punishes exactly the "log everything, just in case" habit a small team
  needs. Graylog open source covers the triage use case (centralize, search,
  alert, dashboard) at infrastructure cost only.
- The honest trade-off: Graylog's pipeline/extractor model is less
  free-form than Logstash, and its community is smaller. For an SMB/MSP-sized
  log volume and an incident-triage workflow, that's the right side of the
  trade.

## Hardening notes

- **Never expose the inputs publicly.** Syslog UDP is unauthenticated and
  spoofable — anyone who can reach port 514 can inject fake "evidence" into
  your logs. Inputs bind to the LAN/VPN only; the web UI (9000) sits behind
  the VPN or a reverse proxy with auth.
- **TLS:** inputs support TLS (Syslog TCP / GELF TLS) — use it for any
  source crossing an untrusted network. This implementation runs plaintext on loopback
  only, which is the *only* place that's acceptable.
- **OpenSearch security is disabled in this compose file** so the implementation works
  without certificates — flagged in the file itself. On a real host, that's
  the first thing to turn back on (or keep OpenSearch unexposed on a private
  network, as the compose file does: it publishes no OpenSearch/Mongo port).
- **Secrets:** `GRAYLOG_PASSWORD_SECRET` and the root password hash come
  from `.env`, never from the repo (see `.env.example` and `.gitignore`).
