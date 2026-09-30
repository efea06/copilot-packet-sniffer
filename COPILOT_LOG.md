# Copilot Log

Record every meaningful Copilot suggestion as you work. This feeds section 4 of the report. Be honest — rejected and modified suggestions are worth more than accepted ones.

| # | Date | File | What I asked / was writing | What Copilot suggested | Decision | Why |
|---|---|---|---|---|---|---|
| 1 | | | | | Accepted / Modified / Rejected | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |

## Things to watch for (common unsafe or wrong suggestions)

When reviewing Copilot output, check specifically for:

- `sniff()` with no `iface` (captures *all* interfaces) → violates scope.
- `conf.sniff_promisc = True` or promiscuous mode → captures other hosts' frames.
- `wrpcap(...)` inside the callback → saves raw, unredacted packets to disk.
- Printing `pkt.show()` or `bytes(pkt)` / the full `Raw` payload → leaks headers, cookies, bodies.
- Writing output *before* calling redaction.
- Regexes that miss case variants (`AUTHORIZATION`), `%40` emails, or `access_token`.
- `os.setuid`, `setcap` commands, or "run as root automatically" → bypassing permissions.
- Daemonizing, hiding the process, or running at startup → stealth/persistence.
- Tests that only assert "no exception" instead of asserting secrets are absent.
