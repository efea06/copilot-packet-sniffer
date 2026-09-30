"""Redaction helpers -- the ethical guardrail.

Every record the sniffer emits passes through ``redact_record`` BEFORE it is
printed or written to disk. Nothing in this module needs Scapy, so it is easy
to unit test.
"""
from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any

REDACTED = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_JWT = "[REDACTED_JWT]"

# Query-string / form / JSON keys whose VALUES must never be logged.
SENSITIVE_KEYS = (
    "password", "passwd", "pwd", "pass", "passphrase",
    "token", "access_token", "refresh_token", "id_token", "auth_token",
    "api_key", "apikey", "key", "secret", "client_secret",
    "session", "sessionid", "session_id", "sid", "jwt", "auth", "code",
)

# HTTP headers whose values must never be logged.
SENSITIVE_HEADERS = (
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token",
)

# Longest first so "access_token" wins over "token".
_KEYS_ALT = "|".join(sorted((re.escape(k) for k in SENSITIVE_KEYS), key=len, reverse=True))
_HEADERS_ALT = "|".join(re.escape(h) for h in SENSITIVE_HEADERS)

_HEADER_RE = re.compile(rf"(?im)^\s*({_HEADERS_ALT})\s*:.*$")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
# "password": "hunter2"  (JSON bodies)
_JSON_KV_RE = re.compile(rf'(?i)("(?:{_KEYS_ALT})"\s*:\s*")([^"]*)(")')
# password=hunter2 / token: abc  (query strings, forms, cookies)
_KV_RE = re.compile(rf"(?i)(?<![A-Za-z0-9_])((?:{_KEYS_ALT})\s*[=:]\s*)([^&\s;,\"'#]+)")
# Plain and URL-encoded (%40) emails.
_EMAIL_RE = re.compile(r"(?i)[A-Za-z0-9._+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4_IN_TEXT_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")

_IP_FIELDS = {"src_ip", "dst_ip"}
_MAC_FIELDS = {"src_mac", "dst_mac"}


def mask_ip(addr: str | None) -> str | None:
    """Partially mask an IP address.

    IPv4: 192.168.1.42 -> 192.168.1.xxx
    IPv6: keep the first 4 groups (the /64 network), hide the host part.
    Anything that is not a valid IP is fully redacted.
    """
    if addr is None or addr == "":
        return addr
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return REDACTED
    if ip.version == 4:
        a, b, c, _ = str(ip).split(".")
        return f"{a}.{b}.{c}.xxx"
    groups = ip.exploded.split(":")
    return ":".join(groups[:4]) + ":xxxx:xxxx:xxxx:xxxx"


def mask_mac(mac: str | None) -> str | None:
    """Keep only the vendor prefix (OUI) of a MAC address."""
    if not mac:
        return mac
    parts = re.split(r"[:-]", mac)
    if len(parts) != 6:
        return REDACTED
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def redact_text(text: str) -> str:
    """Remove secrets, emails and host parts of IPv4 addresses from free text."""
    if not text:
        return text
    out = _HEADER_RE.sub(lambda m: f"{m.group(1)}: {REDACTED}", text)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _JWT_RE.sub(REDACTED_JWT, out)
    out = _JSON_KV_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", out)
    out = _KV_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
    out = _EMAIL_RE.sub(REDACTED_EMAIL, out)
    out = _IPV4_IN_TEXT_RE.sub(lambda m: f"{m.group(1)}.xxx", out)
    return out


def _redact_value(key: str | None, value: Any) -> Any:
    if key in _IP_FIELDS and isinstance(value, str):
        return mask_ip(value)
    if key in _MAC_FIELDS and isinstance(value, str):
        return mask_mac(value)
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, v) for v in value]
    return value  # ints, bools, None


def redact_record(record: dict) -> dict:
    """Return a redacted deep copy of a decoded packet record."""
    return _redact_value(None, copy.deepcopy(record))
