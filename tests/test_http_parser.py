"""Unit tests for the HTTP request-line parser (no Scapy required)."""
from http_parser import parse_http_request


def test_simple_get():
    r = parse_http_request(b"GET /index.html HTTP/1.1\r\nHost: lab.local\r\n\r\n")
    assert (r["method"], r["host"], r["path"], r["version"]) == ("GET", "lab.local", "/index.html", "HTTP/1.1")
    assert r["sensitive_headers_seen"] == []


def test_sensitive_header_names_recorded_but_not_values():
    raw = b"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer SECRET\r\nCookie: sid=1\r\n\r\n"
    r = parse_http_request(raw)
    assert r["sensitive_headers_seen"] == ["authorization", "cookie"]
    assert "SECRET" not in str(r)


def test_post_body_length_only():
    r = parse_http_request(b"POST /login HTTP/1.1\r\nHost: h\r\n\r\nuser=bob&password=x")
    assert r["method"] == "POST"
    assert r["body_bytes"] == len(b"user=bob&password=x")
    assert "password=x" not in str(r)


def test_absolute_form_target():
    r = parse_http_request(b"GET http://proxy.lab/a?b=1 HTTP/1.1\r\n\r\n")
    assert r["host"] == "proxy.lab" and r["path"] == "/a?b=1"


def test_bare_lf_line_endings():
    r = parse_http_request(b"GET /x HTTP/1.0\nHost: h\n\n")
    assert r["host"] == "h"


def test_non_http_returns_none():
    assert parse_http_request(b"\x16\x03\x01\x00\xa5binary-tls") is None
    assert parse_http_request(b"HTTP/1.1 200 OK\r\n\r\n") is None  # responses are not requests
    assert parse_http_request(b"") is None
