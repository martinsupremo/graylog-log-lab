# Dashboard design: "First five minutes" triage board

One dashboard, built for one job: when a ticket or an alert lands, this board
should answer *is it auth, is it the VPN, is it DNS, and is it just one user
or everyone?*, before you run a single manual search. Everything that
doesn't serve that question lives in saved searches
(docs/search-queries.md), not on the board.

## Widgets

| # | Widget | Type | Answers |
|---|--------|------|---------|
| 1 | Failed auth events, last 24h | Line chart (count over time) | "Is auth failure volume normal, or spiking?" A spike is the brute-force early warning. |
| 2 | Top source IPs by failed logons | Bar chart / data table (top 10) | "Is one IP doing this?" Concentration = attack or broken service; spread = noise. |
| 3 | Auth success vs failure ratio | Single number + % trend | "Is anyone getting in at all?" Failures up + successes flat = outage or lockout storm; one success inside a failure spike = investigate now. |
| 4 | VPN peer status | Data table: peer, last successful handshake, retries in last hour | "Whose tunnel is actually broken?" Separates one flapping peer from a server-wide problem at a glance. |
| 5 | Top DNS domains queried | Bar chart (top 10) | "What's everyone reaching for: and is anything odd on the list?" Also proves DNS is alive when "the internet is down" tickets land. |
| 6 | Event volume by source host | Stacked area chart | "Which system went quiet: or went loud?" A host that stops logging is a finding in itself (agent down, host down, or someone covering tracks). |

## Layout

Three-column grid, ordered by the triage sequence: eyes land top-left and
work down the questions in order:

```
┌────────────────────┬────────────────────┬────────────────────┐
│ 1. Failed auth     │ 2. Top source IPs  │ 3. Success/failure │
│    trend (24h)     │    by failures     │    ratio           │
├────────────────────┴────────────────────┼────────────────────┤
│ 4. VPN peer status (wide table)         │ 5. Top DNS         │
│                                         │    domains         │
├─────────────────────────────────────────┴────────────────────┤
│ 6. Event volume by source host (full width)                  │
└──────────────────────────────────────────────────────────────┘
```

Default time range: last 24 hours, auto-refresh 30s while the board is open.
Every widget is a saved search underneath, so clicking through from any
widget lands you in the raw events with the same filters. The board finds
the problem, the search does the forensics.

## The triage workflow that uses it

1. **Ticket lands** ("can't log in" / "VPN down" / "everything's slow").
   Open the board, don't open a search yet. Ten seconds.
2. **Read the shape.** Auth spike (widget 1)? One IP (widget 2)? One peer
   down or all (widget 4)? A host gone silent (widget 6)? The board turns
   "something's wrong" into one of four shapes: attack, one-user, one-service,
   or everything.
3. **Click through** the widget that matches the shape into its saved
   search, narrowed to the ticket's time window.
4. **Confirm or kill the hypothesis** with one targeted query from
   docs/search-queries.md (e.g. success-after-failures for an auth spike,
   handshake presence/absence for a VPN report).
5. **Act or escalate with evidence:** the ticket note quotes the actual log
   lines and counts ("214 failures from 198.51.100.23 between 14:52–15:04,
   followed by one successful logon to deploy"), not "logs looked weird."

With the log generator you can rehearse the whole loop: run
`--scenario bruteforce`, watch widgets 1–3 react, then run the click-through
searches; run `--scenario vpn-flap` and watch widget 4 isolate the bad peer.
