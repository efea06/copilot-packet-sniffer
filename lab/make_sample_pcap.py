#!/usr/bin/env python3
"""Build lab/sample.pcap from SYNTHETIC packets (no real traffic, no root needed).

Used by pcap mode (Mode 2) and as the fallback when capture privileges are missing.
"""
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

OUT = Path(__file__).resolve().parent / "sample.pcap"
CLIENT, SERVER, RESOLVER = "192.168.56.10", "192.168.56.20", "192.168.56.1"
ETH = Ether(src="08:00:27:aa:bb:01", dst="08:00:27:aa:bb:02")


def http(path: str, extra_headers: str = "", method: str = "GET", body: str = "") -> bytes:
    head = f"{method} {path} HTTP/1.1\r\nHost: {SERVER}\r\nUser-Agent: lab-client\r\n{extra_headers}"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    return (head + "\r\n" + body).encode()


def build_packets():
    return [
        ETH / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=40001, dport=53)
        / DNS(id=1, rd=1, qd=DNSQR(qname="victim.lab.local")),
        ETH / IP(src=RESOLVER, dst=CLIENT) / UDP(sport=53, dport=40001)
        / DNS(id=1, qr=1, qd=DNSQR(qname="victim.lab.local"), an=DNSRR(rrname="victim.lab.local", rdata=SERVER)),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=80, flags="S"),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=80, flags="PA") / Raw(http("/index.html")),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50001, dport=80, flags="PA")
        / Raw(http("/login?user=alice&password=hunter2")),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50002, dport=80, flags="PA")
        / Raw(http("/api/items?token=FAKE-TOKEN-abc123",
                   "Authorization: Bearer FAKE.JWT.VALUE\r\nCookie: sessionid=FAKE-999\r\n")),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50003, dport=80, flags="PA")
        / Raw(http("/contact?email=alice@example.com")),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50004, dport=80, flags="PA")
        / Raw(http("/login", "Content-Type: application/x-www-form-urlencoded\r\n", "POST",
                   "user=bob&password=correcthorse")),
        ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=50005, dport=443, flags="PA")
        / Raw(b"\x16\x03\x01\x00\xa5fake-tls-client-hello"),
        ETH / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=40002, dport=123) / Raw(b"ntp-noise-filtered-out"),
    ]


def build(out: Path = OUT) -> Path:
    pkts = build_packets()
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i
    wrpcap(str(out), pkts)
    print(f"Wrote {len(pkts)} synthetic packets to {out}")
    return out


if __name__ == "__main__":
    build()
