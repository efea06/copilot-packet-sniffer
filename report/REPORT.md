# Copilot-Assisted Packet Sniffer — Report

**Name:** ____________  **Course:** ____________  **Date:** ____________
**Repo:** https://github.com/____________/copilot-packet-sniffer

> Target length: 2–3 pages. Replace every _[bracketed instruction]_ with your own content. Sections 2 and 4 must describe **your** lab run and **your** Copilot session.

## 1. Environment and approach

_[2–4 sentences. OS/VM (e.g., Ubuntu 24.04 in VirtualBox), Python version, Scapy version, capture mode used (live loopback, pcap, or both), and why.]_

The sniffer uses Scapy's `sniff()` with an allowlisted interface (`lo`), a BPF filter (`tcp port 8080 or udp port 53`), `count=25`, and a `prn` callback that decodes each packet, redacts it, and only then prints it. Traffic was generated locally with `lab/victim_server.py` and `lab/generate_traffic.py`, which use fake credentials.

## 2. What I captured

_[Insert 2–3 screenshots from `screenshots/` and/or short excerpts from your `.jsonl` log. For each, write one sentence explaining what the reader is seeing at each layer.]_

**Figure 1** — DNS query on loopback: _[screenshot]_
Ethernet (zeroed on `lo`) → IPv4 127.0.0.xxx → UDP to port 53 → DNS query for `victim.lab.local` (type A).

**Figure 2** — HTTP GET with credentials in the query string: _[screenshot]_
TCP to port 8080 → HTTP request line `GET /login?user=alice&password=[REDACTED]`.

**Figure 3** — Request carrying `Authorization` and `Cookie` headers: _[screenshot]_
Only the header names are reported; values never leave the tool.

_[Optional: a short note on the TCP handshake (SYN, SYN-ACK, ACK) or the encrypted-traffic note you saw on port 443.]_

## 3. What I redacted and why

| Field | Treatment | Why |
|---|---|---|
| IP addresses | Last octet → `xxx` (IPv6: host half) | Identifies a specific device/person; the subnet is enough for learning |
| MAC addresses | Vendor prefix only | Hardware IDs are persistent, trackable identifiers |
| `Authorization` / Bearer / Basic / JWT | `[REDACTED]` | Directly usable credentials — replaying them grants access |
| `Cookie` / `Set-Cookie` / session IDs | `[REDACTED]` | Session tokens allow session hijacking without a password |
| `password=`, `token=`, `api_key=`, etc. | Value → `[REDACTED]` | Secrets often leak through query strings and form posts |
| Emails | `[REDACTED_EMAIL]` | Personal data (PII) |
| HTTP bodies | Never logged, length only | Bodies carry form posts, JSON credentials, and personal content |

Design decision: the decoder emits an **allowlist** of fields rather than dumping the packet and trying to scrub it afterward. Regex redaction is a second layer, not the only one. _[Add 1–2 sentences on any edge case you found or tested, e.g., `%40`-encoded emails or upper-case header names.]_

## 4. Copilot reflection: what I accepted, modified, and rejected

_[Summarize 3–5 entries from `COPILOT_LOG.md`. For each: what you prompted, what Copilot produced, what you did, and why. Include at least one rejection and one modification.]_

| Suggestion | Decision | Reason |
|---|---|---|
| _[e.g., what Copilot proposed for the sniff() call]_ | | |
| _[e.g., its redaction regex]_ | | |
| _[e.g., its test scaffold]_ | | |

_[2–3 sentences: what Copilot was good at, where it was unsafe or wrong, and what you'd do differently.]_

## 5. Risk memo: why sniffers are powerful, and how defenders detect misuse

**Why they are powerful.** A sniffer sees everything that crosses an interface in cleartext: DNS lookups reveal every site a device visits, unencrypted HTTP exposes URLs, cookies, and credentials, and even encrypted traffic leaks metadata (who talks to whom, when, how much, and the server name in TLS). On a shared segment, or combined with ARP spoofing, one compromised machine can observe many others. That is why the same tool that helps an administrator debug a network can enable credential theft and surveillance.

**How defenders detect misuse.**

- **Promiscuous-mode detection:** `ip link` shows the `PROMISC` flag; network tools can probe hosts with frames sent to a bogus MAC address and see which host responds.
- **Host monitoring:** `auditd` or EDR rules alert on raw-socket creation, `CAP_NET_RAW` use, or execution of `tcpdump`, Wireshark, or Scapy by unexpected users; large unexplained `.pcap` files are a red flag.
- **Network controls:** switches with port security and 802.1X limit what an unauthorized device can join; Dynamic ARP Inspection, DHCP snooping, and `arpwatch` catch ARP spoofing used to redirect traffic to a sniffer.
- **Anomaly detection:** IDS tools (e.g., Zeek, Suricata) flag ARP floods, duplicate IP-to-MAC mappings, and unusual traffic patterns.

**How defenders reduce the damage.** Encrypt everything (HTTPS with HSTS, TLS for internal services, DNS over HTTPS/TLS), avoid secrets in URLs, use short-lived tokens, segment networks, and use WPA3 on Wi-Fi so that captured traffic is far less useful.

**Takeaway.** _[1–2 sentences in your own words on what this lab changed about how you think about unencrypted traffic or about using AI assistants for security tools.]_
