"""Decoder + end-to-end pipeline + guardrail tests. Uses crafted packets only -- no network, no root."""
import io
import json

import pytest

pytest.importorskip("scapy")

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402

import sniffer  # noqa: E402
from decoder import decode_packet  # noqa: E402

ETH = Ether(src="08:00:27:aa:bb:01", dst="08:00:27:aa:bb:02")
SECRET_HTTP = (b"GET /login?user=alice&password=hunter2&email=alice@example.com HTTP/1.1\r\n"
               b"Host: 192.168.56.20\r\nAuthorization: Bearer TOPSECRET\r\nCookie: sessionid=S3SS10N\r\n\r\n")


def http_pkt():
    return ETH / IP(src="192.168.56.10", dst="192.168.56.20") / TCP(sport=50000, dport=80, flags="PA") / Raw(SECRET_HTTP)


def dns_pkt():
    return ETH / IP(src="192.168.56.10", dst="192.168.56.1") / UDP(sport=40000, dport=53) / DNS(
        id=7, rd=1, qd=DNSQR(qname="victim.lab.local"))


# ------------------------------------------------------------------ decoding
def test_decode_http_layers_and_fields():
    rec = decode_packet(http_pkt())
    assert rec["layers"] == ["Ethernet", "IPv4", "TCP", "HTTP"]
    assert (rec["src_port"], rec["dst_port"], rec["proto"]) == (50000, 80, "TCP")
    assert rec["http"]["method"] == "GET"
    assert rec["http"]["host"] == "192.168.56.20"
    assert rec["http"]["path"].startswith("/login")


def test_decode_dns_query():
    rec = decode_packet(dns_pkt())
    assert rec["proto"] == "UDP" and "DNS" in rec["layers"]
    assert rec["dns"]["kind"] == "query"
    assert rec["dns"]["queries"] == [{"name": "victim.lab.local", "type": "A"}]


def test_decode_loopback_packet_without_ethernet():
    rec = decode_packet(IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=1, dport=53) / DNS(qd=DNSQR(qname="a.lab")))
    assert rec["layers"][0] == "Raw/Loopback"
    assert rec["dns"]["queries"][0]["name"] == "a.lab"


def test_tls_is_noted_not_decoded():
    pkt = ETH / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443) / Raw(b"\x16\x03\x01binary")
    assert "encrypted" in decode_packet(pkt)["note"]


# ------------------------------------------------------- end-to-end pipeline
def test_pipeline_output_contains_no_secrets():
    stream, out = io.StringIO(), io.StringIO()
    writer = sniffer.RecordWriter(fmt="json", stream=stream, out=out)
    writer(http_pkt())
    writer(dns_pkt())
    text = stream.getvalue() + out.getvalue()
    for secret in ("hunter2", "TOPSECRET", "S3SS10N", "alice@example.com", "192.168.56.10", "aa:bb:01"):
        assert secret not in text, f"leaked {secret}"
    first = json.loads(out.getvalue().splitlines()[0])
    assert first["src_ip"] == "192.168.56.xxx"
    assert first["http"]["sensitive_headers_seen"] == ["authorization", "cookie"]
    assert writer.stats["packets"] == 2


def test_malformed_packet_does_not_crash(monkeypatch):
    monkeypatch.setattr(sniffer, "decode_packet", lambda p: (_ for _ in ()).throw(ValueError("bad")))
    writer = sniffer.RecordWriter(stream=io.StringIO())
    writer(http_pkt())
    assert writer.stats["errors"] == 1


# ---------------------------------------------------------------- guardrails
def test_allowlist_blocks_unlisted_interface(tmp_path):
    allow = sniffer.load_allowlist(tmp_path / "missing.txt")
    sniffer.check_interface("lo", allow)
    with pytest.raises(PermissionError):
        sniffer.check_interface("eth0", allow)


def test_allowlist_file_adds_lab_interface(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# comment\nvboxnet0  # lab network\n")
    assert "vboxnet0" in sniffer.load_allowlist(f)


def test_unlisted_interface_exits_with_error(monkeypatch):
    monkeypatch.setattr(sniffer, "sniff", lambda **kw: pytest.fail("must not sniff"))
    assert sniffer.main(["--iface", "eth0"]) == 2


def test_falls_back_to_pcap_without_privileges(monkeypatch, tmp_path):
    fake_pcap = tmp_path / "x.pcap"
    fake_pcap.write_bytes(b"")
    calls = {}
    monkeypatch.setattr(sniffer, "has_capture_privileges", lambda: False)
    monkeypatch.setattr(sniffer, "sniff", lambda **kw: calls.update(kw))
    assert sniffer.main(["--iface", "lo", "--fallback-pcap", str(fake_pcap)]) == 0
    assert calls["offline"] == str(fake_pcap)
    assert "iface" not in calls


def test_count_is_capped():
    with pytest.raises(SystemExit):
        sniffer.parse_args(["--count", "100000"])


def test_refuses_raw_pcap_output():
    with pytest.raises(SystemExit):
        sniffer.parse_args(["--out", "capture.pcap"])
