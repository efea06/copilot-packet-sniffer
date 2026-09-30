"""Unit tests for the redaction guardrail (no Scapy required)."""
import pytest

from redaction import REDACTED, REDACTED_EMAIL, mask_ip, mask_mac, redact_record, redact_text


@pytest.mark.parametrize("ip, expected", [
    ("192.168.1.42", "192.168.1.xxx"),
    ("127.0.0.1", "127.0.0.xxx"),
    ("10.0.0.255", "10.0.0.xxx"),
])
def test_mask_ipv4(ip, expected):
    assert mask_ip(ip) == expected


def test_mask_ipv6_hides_host_part():
    assert mask_ip("2001:db8::1") == "2001:0db8:0000:0000:xxxx:xxxx:xxxx:xxxx"


def test_mask_ip_invalid_is_fully_redacted():
    assert mask_ip("not-an-ip") == REDACTED


def test_mask_mac_keeps_vendor_prefix_only():
    assert mask_mac("08:00:27:aa:bb:01") == "08:00:27:xx:xx:xx"


def test_authorization_header_redacted():
    out = redact_text("Host: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n")
    assert "dXNlcjpwYXNz" not in out
    assert "Authorization: [REDACTED]" in out


def test_cookie_and_set_cookie_redacted():
    out = redact_text("Cookie: sessionid=abc; theme=dark\nSet-Cookie: sid=zzz; HttpOnly")
    assert "abc" not in out and "zzz" not in out


def test_bearer_token_anywhere():
    assert "SECRET123" not in redact_text("sent bearer SECRET123 to api")


def test_jwt_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part-123"
    assert "eyJ" not in redact_text(f"x={jwt}")


@pytest.mark.parametrize("path, secret", [
    ("/login?user=alice&password=hunter2", "hunter2"),
    ("/api?token=abc123&page=2", "abc123"),
    ("/cb?access_token=XYZ", "XYZ"),
    ("/x?API_KEY=k-999", "k-999"),
    ("/x?pwd=p1&sessionid=s2", "s2"),
])
def test_sensitive_query_params(path, secret):
    out = redact_text(path)
    assert secret not in out
    assert REDACTED in out


def test_non_sensitive_params_kept():
    assert redact_text("/items?page=2&sort=asc") == "/items?page=2&sort=asc"


def test_json_body_secret():
    assert "hunter2" not in redact_text('{"user": "a", "password": "hunter2"}')


@pytest.mark.parametrize("text", ["alice@example.com", "alice%40example.com", "Bob.Smith+lab@uni.edu"])
def test_emails_redacted(text):
    assert redact_text(f"/contact?to={text}") == f"/contact?to={REDACTED_EMAIL}"


def test_ipv4_inside_text_masked():
    assert redact_text("Host: 192.168.56.20:80") == "Host: 192.168.56.xxx:80"


def test_redact_record_is_deep_and_does_not_mutate_input():
    rec = {
        "src_ip": "192.168.56.10", "dst_ip": "192.168.56.20", "src_mac": "08:00:27:aa:bb:01",
        "http": {"host": "192.168.56.20", "path": "/login?password=hunter2&email=a@b.com"},
        "dns": {"queries": [{"name": "victim.lab.local"}]},
        "length": 100,
    }
    out = redact_record(rec)
    assert out["src_ip"] == "192.168.56.xxx"
    assert out["src_mac"] == "08:00:27:xx:xx:xx"
    assert "hunter2" not in out["http"]["path"]
    assert REDACTED_EMAIL in out["http"]["path"]
    assert out["dns"]["queries"][0]["name"] == "victim.lab.local"
    assert out["length"] == 100
    assert rec["http"]["path"].endswith("a@b.com")  # original untouched
