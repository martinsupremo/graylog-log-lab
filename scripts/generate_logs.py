#!/usr/bin/env python3
"""Synthetic log generator for the Graylog log-analysis implementation.

Sends realistic RFC 3164-style syslog over UDP to a Graylog syslog input
(default 127.0.0.1:514). Pure Python 3 standard library -- no dependencies.

Event types emitted in normal mode (mixed, weighted):
  - sshd   : SSH auth success / failure, invalid-user probes, disconnects
  - sudo   : sudo sessions and commands
  - kernel : WireGuard (wireguard: wg0:) handshake / retry lines
  - dnsmasq: DNS queries A/AAAA/PTR
  - MSWinEventLog : Windows-style logon events relayed by a "win-collector"

Incident scenario modes:
  --scenario bruteforce : burst of failed SSH logins from ONE source IP,
                          then (on purpose) one successful login from the
                          same IP, so the "success after failures" search
                          in docs/search-queries.md finds something real.
  --scenario vpn-flap   : repeated WireGuard handshake failures from ONE
                          peer, spaced out like a misbehaving tunnel.

All IPs are RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24)
and all usernames/hosts are invented fixtures. Nothing here describes a
real system.

Examples:
  python3 generate_logs.py                     # 200 events @ 5/s to :514
  python3 generate_logs.py --count 50 --rate 20
  python3 generate_logs.py --scenario bruteforce --count 30 --dry-run
"""

import argparse
import random
import socket
import sys
import time
from datetime import datetime

# --- syslog scaffolding -----------------------------------------------------

FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "authpriv": 10,
              "local0": 16}
SEVERITIES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3,
              "warning": 4, "notice": 5, "info": 6, "debug": 7}


def syslog_line(facility, severity, hostname, tag, message, pid=None):
    """Format one RFC 3164 BSD-syslog line."""
    pri = FACILITIES[facility] * 8 + SEVERITIES[severity]
    now = datetime.now()
    # BSD syslog pads the day of month with a space ("Oct  5"), not a zero.
    timestamp = "%s %2d %s" % (now.strftime("%b"), now.day,
                               now.strftime("%H:%M:%S"))
    tag_part = "%s[%d]" % (tag, pid) if pid else tag
    return "<%d>%s %s %s: %s" % (pri, timestamp, hostname, tag_part, message)


# --- fixture data -------------------------------------------------------

# Client / user hosts on the "internal" documentation range.
LAN_IPS = ["192.0.2.%d" % n for n in (10, 11, 15, 22, 34, 41, 57)]
# "External" documentation range.
WAN_IPS = ["198.51.100.%d" % n for n in (7, 23, 44, 68, 90, 121)]
ATTACKER_IP = "198.51.100.23"          # the brute-force source
FLAPPING_PEER_IP = "198.51.100.44"     # the VPN-flap peer

USERS = ["alice", "bob", "carla", "diego", "svc-backup", "deploy"]
# Usernames a brute-forcer would try. All invented / generic.
GUESS_USERS = ["root", "admin", "oracle", "test", "ubuntu", "postgres",
               "pi", "support"]
WINDOWS_USERS = ["alice", "bob", "carla", "Administrator", "guest"]

DOMAINS = [
    "fileserver.home.arpa", "vpn.home.arpa", "mail.home.arpa",
    "updates.example.org", "cdn.example.net", "docs.example.com",
]
SUDO_COMMANDS = [
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl status openvpn",
    "/usr/sbin/ufw status",
    "/usr/bin/apt update",
    "/usr/bin/tail -n 100 /var/log/auth.log",
    "/usr/bin/journalctl -u sshd",
]
# WireGuard peer "public keys" are printed as placeholders, never real keys.
WG_PEERS = ["PEER-A", "PEER-B", "PEER-C", "PEER-D"]
UPTIME = [random.uniform(1000, 900000) for _ in range(8)]


def event_sshd(rng):
    host = "vpnserver"
    user = rng.choice(USERS)
    ip = rng.choice(LAN_IPS if rng.random() < 0.6 else WAN_IPS)
    pid = rng.randint(1000, 30000)
    roll = rng.random()
    if roll < 0.45:
        msg = ("Accepted publickey for %s from %s port %d ssh2" %
               (user, ip, rng.randint(1024, 65535)))
        return syslog_line("authpriv", "info", host, "sshd", msg, pid)
    if roll < 0.75:
        msg = ("Failed password for %s from %s port %d ssh2" %
               (user, ip, rng.randint(1024, 65535)))
        return syslog_line("authpriv", "info", host, "sshd", msg, pid)
    if roll < 0.85:
        guess = rng.choice(GUESS_USERS)
        msg = ("Invalid user %s from %s port %d" %
               (guess, rng.choice(WAN_IPS), rng.randint(1024, 65535)))
        return syslog_line("authpriv", "info", host, "sshd", msg, pid)
    msg = ("Disconnected from user %s %s port %d" %
           (user, ip, rng.randint(1024, 65535)))
    return syslog_line("authpriv", "info", host, "sshd", msg, pid)


def event_sudo(rng):
    user = rng.choice(USERS)
    msg = ("%s : TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=%s" %
           (user, rng.randint(0, 4), user, rng.choice(SUDO_COMMANDS)))
    return syslog_line("authpriv", "notice", "vpnserver", "sudo", msg,
                       rng.randint(2000, 30000))


def event_wireguard(rng):
    peer = rng.choice(WG_PEERS)
    ip = rng.choice(WAN_IPS)
    stamp = rng.choice(UPTIME)
    if rng.random() < 0.7:
        msg = ("[%.6f] wireguard: wg0: Handshake for peer %s (%s:51820) "
               "received" % (stamp, peer, ip))
    else:
        msg = ("[%.6f] wireguard: wg0: Handshake for peer %s did not "
               "complete after 5 seconds, retrying (try %d)" %
               (stamp, peer, rng.randint(2, 9)))
    return syslog_line("kern", "info", "vpnserver", "kernel", msg)


def event_dnsmasq(rng):
    qtype = rng.choice(["A", "A", "AAAA", "PTR", "MX"])
    msg = "query[%s] %s from %s" % (qtype, rng.choice(DOMAINS),
                                     rng.choice(LAN_IPS))
    return syslog_line("daemon", "info", "dnsserver", "dnsmasq", msg,
                       rng.randint(800, 2000))


def event_windows(rng):
    """Windows-style logon event, relayed as plain syslog by a collector."""
    user = rng.choice(WINDOWS_USERS)
    src = rng.choice(LAN_IPS if rng.random() < 0.7 else WAN_IPS)
    ws = rng.choice(["WS-FIN-04", "WS-OPS-02", "LAPTOP-ALICE", "SRV-APP-01"])
    if rng.random() < 0.6:  # 4624 = successful logon
        msg = ("EventID=4624 LogonType=3 Account=%s SourceIP=%s "
               "Workstation=%s Status=Success" % (user, src, ws))
    else:                   # 4625 = failed logon
        msg = ("EventID=4625 LogonType=3 Account=%s SourceIP=%s "
               "Workstation=%s Status=Failure "
               "FailureReason=UnknownUserOrBadPassword" % (user, src, ws))
    return syslog_line("local0", "info", "win-collector", "MSWinEventLog",
                       msg)


NORMAL_EVENTS = [
    (event_sshd, 0.35),
    (event_wireguard, 0.20),
    (event_dnsmasq, 0.20),
    (event_windows, 0.15),
    (event_sudo, 0.10),
]


def normal_event(rng):
    roll = rng.random()
    running = 0.0
    for fn, weight in NORMAL_EVENTS:
        running += weight
        if roll < running:
            return fn(rng)
    return NORMAL_EVENTS[-1][0](rng)


# --- incident scenarios -----------------------------------------------------

def scenario_bruteforce(rng, count):
    """Many failed SSH logins from ONE IP, then one success from that IP."""
    lines = []
    for i in range(max(count - 1, 0)):
        user = rng.choice(GUESS_USERS)
        msg = ("Failed password for %s from %s port %d ssh2" %
               (user, ATTACKER_IP, rng.randint(1024, 65535)))
        lines.append(syslog_line("authpriv", "info", "vpnserver", "sshd",
                                 msg, rng.randint(1000, 30000)))
        if i % 9 == 4:  # sprinkle normal background traffic through the burst
            lines.append(event_dnsmasq(rng))
    # The line that turns a noisy alert into a possible compromise:
    msg = ("Accepted password for deploy from %s port %d ssh2" %
           (ATTACKER_IP, rng.randint(1024, 65535)))
    lines.append(syslog_line("authpriv", "info", "vpnserver", "sshd", msg,
                             rng.randint(1000, 30000)))
    return lines


def scenario_vpn_flap(rng, count):
    """One peer whose handshake never completes, over and over."""
    lines = []
    for _ in range(count):
        stamp = rng.choice(UPTIME)
        msg = ("[%.6f] wireguard: wg0: Handshake for peer PEER-B did not "
               "complete after 5 seconds, retrying (try %d)" %
               (stamp, rng.randint(2, 15)))
        lines.append(syslog_line("kern", "info", "vpnserver", "kernel", msg))
        if rng.random() < 0.25:  # other peers keep working fine
            lines.append(event_wireguard(rng))
    return lines


# --- main -------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Synthetic syslog generator for the Graylog implementation.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Graylog syslog input host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=514,
                        help="UDP port of the syslog input (default 514, the "
                             "HOST-side port; compose maps 514->1514 inside "
                             "the container)")
    parser.add_argument("--count", type=int, default=200,
                        help="number of events to emit (default 200)")
    parser.add_argument("--rate", type=float, default=5.0,
                        help="events per second; 0 = as fast as possible")
    parser.add_argument("--scenario", choices=["bruteforce", "vpn-flap"],
                        default=None,
                        help="emit an incident scenario instead of a mix")
    parser.add_argument("--seed", type=int, default=None,
                        help="random seed, for reproducible runs")
    parser.add_argument("--dry-run", action="store_true",
                        help="print events to stdout instead of sending UDP")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)

    if args.scenario == "bruteforce":
        events = scenario_bruteforce(rng, args.count)
    elif args.scenario == "vpn-flap":
        events = scenario_vpn_flap(rng, args.count)
    else:
        events = [normal_event(rng) for _ in range(args.count)]

    sock = None
    if not args.dry_run:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    delay = (1.0 / args.rate) if args.rate > 0 else 0.0
    sent = 0
    try:
        for line in events:
            if args.dry_run:
                print(line)
            else:
                sock.sendto(line.encode("utf-8") + b"\n",
                            (args.host, args.port))
            sent += 1
            if delay:
                time.sleep(delay)
    finally:
        if sock is not None:
            sock.close()
    print("emitted %d events -> %s:%d%s" %
          (sent, args.host, args.port,
           " (dry-run)" if args.dry_run else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
