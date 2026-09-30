"""Turn a Scapy packet into a plain dict (NOT yet redacted).

Decodes: Ethernet (or raw/loopback), IPv4/IPv6, TCP/UDP, DNS queries,
and plaintext HTTP request lines.
"""
from __future__ import annotations

from datetime import datetime, timezone

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from http_parser import parse_http_request

TLS_PORTS = {443, 853, 993, 995, 8443}


def _dns_questions(dns: DNS) -> list[DNSQR]:
    """Return DNS questions; works on Scapy <2.6 (chained) and >=2.6 (list)."""
    qd = dns.qd
    if qd is None:
        return []
    if isinstance(qd, list):
        return list(qd)
    questions, q = [], qd
    while isinstance(q, DNSQR):
        questions.append(q)
        q = q.payload
    return questions


def decode_dns(dns: DNS) -> dict:
    queries = []
    for q in _dns_questions(dns):
        name = q.qname.decode(errors="replace") if isinstance(q.qname, bytes) else str(q.qname)
        queries.append({"name": name.rstrip("."), "type": q.sprintf("%qtype%")})
    return {
        "id": int(dns.id),
        "kind": "response" if dns.qr else "query",
        "queries": queries,
        "answer_count": int(dns.ancount or 0),
    }


def decode_packet(pkt: Packet) -> dict:
    rec: dict = {
        "ts": datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(),
        "length": len(pkt),
        "layers": [],
    }

    # Layer 2
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        rec.update(src_mac=eth.src, dst_mac=eth.dst)
        rec["layers"].append("Ethernet")
    else:
        rec["layers"].append("Raw/Loopback")

    # Layer 3
    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec.update(src_ip=ip.src, dst_ip=ip.dst, ttl=int(ip.ttl))
        rec["layers"].append("IPv4")
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec.update(src_ip=ip6.src, dst_ip=ip6.dst, ttl=int(ip6.hlim))
        rec["layers"].append("IPv6")

    # Layer 4
    payload = b""
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.update(proto="TCP", src_port=int(tcp.sport), dst_port=int(tcp.dport), tcp_flags=str(tcp.flags))
        rec["layers"].append("TCP")
        payload = bytes(tcp.payload)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.update(proto="UDP", src_port=int(udp.sport), dst_port=int(udp.dport))
        rec["layers"].append("UDP")

    # Layer 7
    if pkt.haslayer(DNS):
        rec["dns"] = decode_dns(pkt[DNS])
        rec["layers"].append("DNS")
    elif payload:
        http = parse_http_request(payload)
        if http:
            rec["http"] = http
            rec["layers"].append("HTTP")
        elif {rec.get("src_port"), rec.get("dst_port")} & TLS_PORTS:
            rec["note"] = "encrypted (TLS) - payload not decoded"

    return rec


def format_text(rec: dict) -> str:
    """One human-readable line per packet (used with --format text)."""
    src = f"{rec.get('src_ip', '?')}:{rec.get('src_port', '')}".rstrip(":")
    dst = f"{rec.get('dst_ip', '?')}:{rec.get('dst_port', '')}".rstrip(":")
    line = f"{rec['ts']}  {rec.get('proto', '-'):<3}  {src} -> {dst}  len={rec['length']}"
    if "dns" in rec:
        names = ", ".join(f"{q['name']} ({q['type']})" for q in rec["dns"]["queries"])
        line += f"  DNS {rec['dns']['kind']}: {names}"
    if "http" in rec:
        h = rec["http"]
        line += f"  HTTP {h['method']} {h.get('host') or '-'}{h['path']}"
        if h["sensitive_headers_seen"]:
            line += f"  [redacted headers: {', '.join(h['sensitive_headers_seen'])}]"
    if "note" in rec:
        line += f"  ({rec['note']})"
    return line
