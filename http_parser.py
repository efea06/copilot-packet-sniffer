"""Minimal parser for plaintext HTTP/1.x request heads (no Scapy needed)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from redaction import SENSITIVE_HEADERS

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


def parse_http_request(payload: bytes) -> dict | None:
    """Parse the request line and Host header from a TCP payload.

    Returns None if the payload is not the start of an HTTP request.
    Only an allowlist of fields is returned: method, host, path, version,
    the NAMES of sensitive headers that were present (never their values),
    and the body length (never the body itself).
    """
    if not payload:
        return None
    text = payload.decode("iso-8859-1", errors="replace")
    blank_line = re.search(r"\r?\n\r?\n", text)
    if blank_line:
        head, body = text[: blank_line.start()], text[blank_line.end():]
    else:
        head, body = text, ""
    lines = head.splitlines()
    if not lines:
        return None

    parts = lines[0].split(" ")
    if len(parts) != 3:
        return None
    method, target, version = parts
    if method not in HTTP_METHODS or not version.startswith("HTTP/"):
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    host = headers.get("host")
    path = target
    if target.lower().startswith(("http://", "https://")):  # absolute-form (proxies)
        url = urlsplit(target)
        host = host or url.netloc
        path = (url.path or "/") + (f"?{url.query}" if url.query else "")

    return {
        "method": method,
        "host": host,
        "path": path,
        "version": version,
        "sensitive_headers_seen": sorted(h for h in headers if h in SENSITIVE_HEADERS),
        "body_bytes": len(body.encode("iso-8859-1", errors="replace")),
    }
