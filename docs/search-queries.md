# Sample search queries — incident triage

Graylog search uses Lucene-style syntax. Run these in the Search view with
the time range noted; all of them work against the events produced by
`scripts/generate_logs.py`. Tip: extractor fields (`source`, `facility`)
depend on your input configuration — where a field is needed, the
message-text version is given too, because in a real incident you search
with whatever the data actually has.

## 1. Failed logons in the last hour

```
tag:sshd AND message:"Failed password"
```
Time range: last 1 hour.

**What you're looking for:** the baseline. A handful of failures scattered
across users and IPs is normal noise (typos, expired keys). You're reading
for *shape* — is it steady background noise, or a spike?

## 2. Failures grouped by source IP

```
message:"Failed password" OR message:"Invalid user"
```
Then aggregate: group the results by source IP (extract `from <IP>` into a
field first, or use the generator scenario where the message is
consistent), count, sort descending.

**What you're looking for:** concentration. One IP responsible for most
failures = attack or a misconfigured service hammering the server. Spread
evenly = probably just a bad Monday. This is the brute-force detector;
`--scenario bruteforce` makes one IP (198.51.100.23) dominate on purpose.

## 3. Successful login after failures — possible compromise

```
message:"Accepted" AND message:"198.51.100.23"
```
Or generally: run query 2, take the top offending IP, then search that IP
for any success in the same window:

```
tag:sshd AND message:"Accepted" 
```
filtered to the offending source IP.

**What you're looking for:** the single scariest line in auth logs. Failures
alone = someone knocking. A failure burst followed by an "Accepted" from the
same IP = someone got in. That stops being a search exercise and becomes an
incident: identify the account, force a password reset, check what the
session did (query 6). The brute-force scenario deliberately ends with one
such success so this search has a true positive to find.

## 4. VPN handshake failures per peer

```
facility:kernel AND message:"wireguard" AND message:"did not complete"
```

**What you're looking for:** which peer can't finish a handshake, and since
when. Repeated retries for one peer while others complete = that peer's
endpoint, NAT, or key is broken (clock skew and wrong public key are the
classics). *All* peers failing at once = server-side or uplink problem.
`--scenario vpn-flap` generates the one-peer pattern.

## 5. Did the VPN actually go down at 3pm?

```
facility:kernel AND message:"wireguard"
```
Time range: absolute, e.g. 14:30–15:30.

**What you're looking for:** presence vs absence of "Handshake ... received"
lines. Silence from one peer = their client stopped sending. Silence from
every peer = believe the user, it was the server. This is the
verify-the-report search before escalating.

## 6. What did that sudo session do?

```
tag:sudo
```
narrowed to the user and window from query 3.

**What you're looking for:** privilege use following a suspicious logon.
`COMMAND=` in each line tells you exactly what ran as root. Benign admin work
(restarts, log reads) vs. something you've never seen before is usually
obvious at a glance.

## 7. Windows logon failures

```
message:"EventID=4625"
```

**What you're looking for:** the Windows mirror of query 1 — failed logons
relayed by the collector. Group by `Account=` and `SourceIP=` the same way:
many 4625s against one account from one workstation is password-spray
behavior inside the network, not just at the SSH perimeter.

## 8. DNS queries to a specific domain

```
tag:dnsmasq AND message:"query" AND message:"fileserver.lab.local"
```

**What you're looking for:** who is resolving what. Two uses: (a) a user
"can't reach the file server" — if their queries arrive and answers go out,
DNS is innocent and you look at the service; if no queries arrive, their
client isn't even asking your resolver; (b) hunting a suspicious domain —
swap in the domain and you have every internal host that resolved it.
