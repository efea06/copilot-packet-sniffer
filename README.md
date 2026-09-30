[README.md](https://github.com/user-attachments/files/32875899/README.md)
# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

A small Python/Scapy packet sniffer that captures **only lab traffic** (loopback, an instructor-provided lab interface, or a `.pcap` file), decodes Ethernet → IP → TCP/UDP → DNS/HTTP, and **redacts sensitive data before anything is printed or saved**.

## Scope & ethics

You may capture traffic **only**:

- on your own machine, the loopback interface (`lo`), or
- an instructor-provided lab VM/network.

Never capture traffic on shared, public, school, or work networks, or traffic belonging to other people. Unauthorized interception can violate computer-crime and wiretapping laws (for example the U.S. Wiretap Act and the CFAA) and your institution's acceptable-use policy.

The tool enforces this in code:

| Control | Where |
|---|---|
| Live capture only on allowlisted interfaces (`lo` + `allowlist.txt`) | `sniffer.check_interface` |
| "Sniff all interfaces" is refused; `--iface` must be named | `sniffer.main` |
| No privileges → falls back to pcap mode (never escalates) | `sniffer.has_capture_privileges` |
| Every record redacted before output | `sniffer.process_packet` → `redaction.redact_record` |
| Raw packets never written; `--out` is redacted JSON Lines only | `sniffer.parse_args` |
| Packet count capped at 500 (default 25) | `sniffer.parse_args` |
| HTTP bodies never logged, only their length; sensitive header *names* only | `http_parser.parse_http_request` |

## Setup on macOS (what I used)

Tested on a MacBook Air (M3) with macOS Sonoma 14.5 and Python 3.12. No VM needed; live capture uses the loopback interface `lo0`.

```bash
brew install python@3.12
git clone https://github.com/efea06/copilot-packet-sniffer.git
cd copilot-packet-sniffer
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python lab/make_sample_pcap.py
pytest -v
```

Live capture on a Mac: `sudo .venv/bin/python sniffer.py --iface lo0 --count 120` (use `lo0`, not `lo`).

## Setup (Ubuntu/Kali VM, or Windows with WSL2)

```bash
sudo apt update && sudo apt install -y python3 python3-venv git tcpdump
git clone https://github.com/efea06/copilot-packet-sniffer.git
cd copilot-packet-sniffer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python lab/make_sample_pcap.py      # builds lab/sample.pcap (synthetic packets)
pytest -v                            # run the tests
```

Python 3.10+ is required. `tcpdump` is needed for BPF filters in pcap mode.

## Usage

Key parameters map directly onto Scapy's `sniff()`:

| CLI flag | `sniff()` parameter | Meaning |
|---|---|---|
| `-i / --iface` | `iface` | Interface to sniff (must be allowlisted) |
| *(internal)* | `prn` | Callback run per packet: decode → redact → print |
| `-c / --count` | `count` | Packets to capture (default **25**) |
| `-f / --filter` | `filter` | BPF filter, e.g. `"tcp"`, `"port 80"` |
| `-r / --pcap` | `offline` | Read a pcap instead of live capture |

### Mode 2 — read a pcap (no root needed, safest; this is the default)

```bash
python sniffer.py                                    # reads lab/sample.pcap
python sniffer.py --pcap lab/sample.pcap
python sniffer.py --pcap lab/sample.pcap --filter "udp port 53"          # DNS only
python sniffer.py --pcap lab/sample.pcap --format json --out logs/run.jsonl
```

### Mode 1 — live capture on loopback (the "victim" lab)

Open three terminals in the repo with the venv active:

```bash
# Terminal 1: the victim web server (127.0.0.1:8080 only)
python lab/victim_server.py

# Terminal 2: the sniffer (needs root for raw sockets)
sudo .venv/bin/python sniffer.py --iface lo --filter "tcp port 8080 or udp port 53" --count 40

# Terminal 3: generate your own traffic (fake credentials)
python lab/generate_traffic.py
```

If you run Terminal 2 **without** `sudo`, the tool warns and falls back to `lab/sample.pcap`.

### Example output (`--format text`)

Illustrative — your timestamps and lengths will differ.

```
2023-11-14T22:13:21+00:00  UDP  192.168.56.xxx:40001 -> 192.168.56.xxx:53  len=76  DNS query: victim.lab.local (A)
2023-11-14T22:13:25+00:00  TCP  192.168.56.xxx:50002 -> 192.168.56.xxx:80  len=193  HTTP GET 192.168.56.xxx/api/items?token=[REDACTED]  [redacted headers: authorization, cookie]
2023-11-14T22:13:26+00:00  TCP  192.168.56.xxx:50003 -> 192.168.56.xxx:80  len=148  HTTP GET 192.168.56.xxx/contact?email=[REDACTED_EMAIL]
```

JSON Lines records (`--format json` / `--out`) contain: `ts, length, layers, src_mac, dst_mac, src_ip, dst_ip, ttl, proto, src_port, dst_port, tcp_flags, dns{id,kind,queries[],answer_count}, http{method,host,path,version,sensitive_headers_seen,body_bytes}, note`.

## What gets redacted

| Data | Result |
|---|---|
| IPv4 | `192.168.1.42` → `192.168.1.xxx` |
| IPv6 | host half replaced with `xxxx` |
| MAC | vendor prefix kept: `08:00:27:xx:xx:xx` |
| `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token` | `[REDACTED]` (and only header *names* are reported) |
| Bearer/Basic tokens, JWTs | `[REDACTED]` / `[REDACTED_JWT]` |
| `password=`, `token=`, `access_token=`, `api_key=`, `secret=`, `sessionid=`, … | value → `[REDACTED]` |
| Emails (including `%40`-encoded) | `[REDACTED_EMAIL]` |
| HTTP bodies | never logged, only `body_bytes` |

## Project structure

```
sniffer.py            CLI, guardrails, Scapy sniff() + prn callback
decoder.py            Scapy packet -> dict (Ethernet/IP/TCP/UDP/DNS/HTTP)
http_parser.py        Pure-Python HTTP request-line parser
redaction.py          Redaction rules (the ethical guardrail)
allowlist.txt         Extra lab interfaces (instructor-approved only)
lab/victim_server.py  Local "victim" web server on 127.0.0.1:8080
lab/generate_traffic.py  Fake-credential HTTP + DNS traffic on loopback
lab/make_sample_pcap.py  Builds synthetic lab/sample.pcap
tests/                Unit tests: redaction, HTTP parsing, decoding, guardrails
report/REPORT.md      2–3 page report
COPILOT_LOG.md        Running log of Copilot suggestions accepted/rejected
```

## Troubleshooting

- **`PermissionError` / "Operation not permitted"** — live capture needs root. Use `sudo .venv/bin/python ...` or use pcap mode.
- **Filter ignored in pcap mode** — install `tcpdump`.
- **Nothing captured on `lo`** — make sure the filter includes port 8080 (the victim server port) and that you generate traffic *after* starting the sniffer.
- **Windows** — run everything inside WSL2 or the Linux lab VM; native Windows needs Npcap and is not supported here.

---


