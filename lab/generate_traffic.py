#!/usr/bin/env python3
"""Generate FAKE-secret HTTP + DNS traffic on loopback so you sniff only your own traffic.

All credentials below are fake test values. Traffic never leaves 127.0.0.1.
"""
import socket
import time
import urllib.request

from scapy.layers.dns import DNS, DNSQR

BASE = "http://127.0.0.1:8080"

HTTP_REQUESTS = [
    ("GET", "/", {}, None),
    ("GET", "/login?user=alice&password=hunter2", {}, None),
    ("GET", "/api/items?token=FAKE-TOKEN-abc123&page=2", {"Authorization": "Bearer FAKE.JWT.VALUE"}, None),
    ("GET", "/contact?email=alice@example.com", {"Cookie": "sessionid=FAKE-SESSION-999; theme=dark"}, None),
    ("POST", "/login", {"Content-Type": "application/x-www-form-urlencoded"}, b"user=bob&password=correcthorse"),
]

DNS_NAMES = ["victim.lab.local", "api.lab.local", "printer.lab.local"]


def dns_traffic():
    # Queries go to 127.0.0.1:53. No DNS server is needed: the query packets
    # still cross the loopback interface, which is all the sniffer needs.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for i, name in enumerate(DNS_NAMES):
            s.sendto(bytes(DNS(id=1000 + i, rd=1, qd=DNSQR(qname=name))), ("127.0.0.1", 53))
            print(f"DNS query sent: {name}")
            time.sleep(0.3)


def http_traffic():
    for method, path, headers, body in HTTP_REQUESTS:
        req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                print(f"HTTP {method} {path} -> {resp.status}")
        except OSError as exc:
            print(f"HTTP {method} {path} failed ({exc}); is lab/victim_server.py running?")
        time.sleep(0.3)


if __name__ == "__main__":
    dns_traffic()
    http_traffic()
