#!/usr/bin/env python3
"""Copilot-Assisted Packet Sniffer -- lab/loopback traffic only.

Ethical controls built in:
  * Live capture only on allowlisted interfaces (loopback + allowlist.txt).
  * "All interfaces" capture is refused -- --iface must be named explicitly.
  * Falls back to pcap mode if capture privileges are missing (never tries to
    bypass OS permissions).
  * Every record is redacted BEFORE it is printed or written.
  * Raw packets are never saved; output is redacted JSON/text only.
  * Packet count is capped.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import TextIO

from scapy.config import conf
conf.max_list_count = 100_000  # macOS: big routing tables overflow Scapy's 4096 default
from scapy.all import sniff  # noqa: E402
from decoder import decode_packet, format_text
from redaction import redact_record

HERE = Path(__file__).resolve().parent
DEFAULT_FILTER = "tcp port 80 or tcp port 8080 or udp port 53"
DEFAULT_COUNT = 25
MAX_COUNT = 500
DEFAULT_PCAP = HERE / "lab" / "sample.pcap"
ALLOWLIST_FILE = HERE / "allowlist.txt"
BUILTIN_ALLOWED = {"lo", "lo0"}
CAP_NET_RAW = 13

log = logging.getLogger("sniffer")

BANNER = (
    "=== Lab packet sniffer ===\n"
    "Capture ONLY your own machine, loopback, or the instructor-provided lab network.\n"
    "Output is redacted. Raw packets are never saved.\n"
)


# ---------------------------------------------------------------- guardrails
def load_allowlist(path: Path = ALLOWLIST_FILE) -> set[str]:
    allowed = set(BUILTIN_ALLOWED)
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                allowed.add(line)
    return allowed


def check_interface(iface: str, allowlist: set[str]) -> None:
    if iface not in allowlist:
        raise PermissionError(
            f"Interface '{iface}' is not allowlisted. Allowed: {sorted(allowlist)}. "
            "Ask your instructor before adding a lab interface to allowlist.txt."
        )


def has_capture_privileges() -> bool:
    """True if we are root or hold CAP_NET_RAW. We only CHECK -- never escalate."""
    if os.name != "posix":
        return False  # Windows: run inside WSL2 / the Linux lab VM instead
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << CAP_NET_RAW))
    except OSError:
        pass
    return False


# ------------------------------------------------------------------- output
def process_packet(pkt) -> dict:
    """Decode then redact. The ONLY path from packet to output."""
    return redact_record(decode_packet(pkt))


class RecordWriter:
    """Scapy `prn` callback: decode -> redact -> write."""

    def __init__(self, fmt: str = "json", stream: TextIO | None = None, out: TextIO | None = None):
        self.fmt, self.out = fmt, out
        self.stream = stream if stream is not None else sys.stdout
        self.stats: Counter[str] = Counter()

    def __call__(self, pkt) -> None:
        try:
            rec = process_packet(pkt)
        except Exception as exc:  # a malformed packet must not crash the tool
            log.warning("Skipping undecodable packet: %s", exc)
            self.stats["errors"] += 1
            return
        self.stats["packets"] += 1
        self.stats[rec["layers"][-1]] += 1
        line = format_text(rec) if self.fmt == "text" else json.dumps(rec, sort_keys=True)
        print(line, file=self.stream, flush=True)
        if self.out:
            self.out.write(json.dumps(rec, sort_keys=True) + "\n")


def sniff_and_print(iface: str, count: int = DEFAULT_COUNT, bpf: str = DEFAULT_FILTER) -> None:
    """Sniff an allowlisted interface and print redacted packet summaries."""
    if not 1 <= count <= MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    check_interface(iface, load_allowlist())
    if not has_capture_privileges():
        raise PermissionError("Live capture requires root or CAP_NET_RAW")
    sniff(iface=iface, filter=bpf, prn=RecordWriter(fmt="text"), count=count, store=False)


# ---------------------------------------------------------------------- CLI
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ethical lab packet sniffer (loopback / lab / pcap only).",
        epilog=(
            "Examples:\n"
            "  python sniffer.py                                      # read the sample pcap\n"
            '  python sniffer.py --pcap lab/sample.pcap --filter "udp port 53"\n'
            '  sudo .venv/bin/python sniffer.py --iface lo --filter "tcp port 8080" --count 40\n'
            "  python sniffer.py --pcap lab/sample.pcap --format json --out run.jsonl"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("-i", "--iface", help="Allowlisted interface to sniff live (e.g. lo).")
    src.add_argument("-r", "--pcap", type=Path, help="Read packets from a .pcap file (default mode).")
    p.add_argument("-f", "--filter", default=DEFAULT_FILTER, help=f'BPF filter (default: "{DEFAULT_FILTER}")')
    p.add_argument("-c", "--count", type=int, default=DEFAULT_COUNT, help=f"Packets to capture (1-{MAX_COUNT}).")
    p.add_argument("--format", choices=["json", "text"], default="text", help="stdout format.")
    p.add_argument("-o", "--out", type=Path, help="Also write redacted JSON Lines to this file.")
    p.add_argument("--fallback-pcap", type=Path, default=DEFAULT_PCAP, help="pcap used if live capture isn't permitted.")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    if not 1 <= args.count <= MAX_COUNT:
        p.error(f"--count must be between 1 and {MAX_COUNT}")
    if args.out and args.out.suffix in {".pcap", ".pcapng"}:
        p.error("--out writes redacted JSON Lines, not raw packets; use a .jsonl filename")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="[%(levelname)s] %(message)s")
    print(BANNER, file=sys.stderr)

    live = args.iface is not None
    pcap_path = args.pcap or args.fallback_pcap
    if live:
        try:
            check_interface(args.iface, load_allowlist())
        except PermissionError as exc:
            log.error("%s", exc)
            return 2
        if not has_capture_privileges():
            log.warning("No capture privileges (need root or CAP_NET_RAW). Falling back to pcap mode: %s", pcap_path)
            live = False

    if not live and not pcap_path.exists():
        log.error("pcap file not found: %s  (run: python lab/make_sample_pcap.py)", pcap_path)
        return 2

    bpf = args.filter
    if not live and bpf and not shutil.which("tcpdump"):
        log.warning("tcpdump not installed; BPF filter ignored in pcap mode (sudo apt install tcpdump)")
        bpf = None

    out_fh = open(args.out, "w", encoding="utf-8") if args.out else None
    writer = RecordWriter(fmt=args.format, out=out_fh)
    try:
        if live:
            log.info("Live capture on %s | filter=%r | count=%d", args.iface, bpf, args.count)
            sniff(iface=args.iface, filter=bpf, prn=writer, count=args.count, store=False)
        else:
            log.info("Reading %s | filter=%r | count=%d", pcap_path, bpf, args.count)
            sniff(offline=str(pcap_path), filter=bpf, prn=writer, count=args.count, store=False)
    except KeyboardInterrupt:
        log.info("Stopped by user")
    finally:
        if out_fh:
            out_fh.close()

    log.info("Summary: %s", dict(writer.stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
