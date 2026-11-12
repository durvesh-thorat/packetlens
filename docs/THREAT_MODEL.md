# PacketLens Threat Model and Security Review (Windows 11 Offline Scope)

**Status:** Technical hardening and automated security tests implemented (`tests/test_security.py`, `tests/test_dashboard.py`); prepared for experienced human reviewer / maintainer sign-off (`PRODUCTION_ROADMAP.md` M4).

## 1. Deployment Scope and Assets

This threat model applies strictly to the M0 target environment:

- **Host:** One Windows 11 workstation running on-demand offline classic-PCAP analysis,
  loopback HTTP console (`127.0.0.1`), and standalone HTML report generation.
- **Out of scope:** Linux live `AF_PACKET` capture, unencrypted remote HTTP exposure,
  multi-user authentication, and automated traffic blocking.

### Sensitive Assets

| Asset | Sensitivity | Storage / Exposure |
|---|---|---|
| Raw PCAP captures | High (addresses, DNS names, payloads) | Local filesystem supplied by operator |
| `packetlens.db` (SQLite + WAL/SHM) | High (incidents, host peers, DNS/alert details) | Local filesystem; 90-day closed-record retention |
| Dashboard session token | Medium-High (authorizes `ack`/`close` transitions) | Printed to terminal stdout; injected into `index.html` `<meta>` with `Cache-Control: no-store` |
| Standalone HTML reports | High (exported incidents, hosts, policies) | Local HTML files exported via `packetlens report` |

## 2. Trust Boundaries

1. **Untrusted Network Traffic (`PCAP` -> `pcap.py` / `parsers.py` -> `detectors.py` / `engine.py`):**
   Packet headers, lengths, timestamps, MAC/IP addresses, and DNS query labels are
   attacker-controlled.
2. **Persistence & Query Boundary (`engine.py` / `dashboard.py` -> `store.py`):**
   Untrusted packet fields and operator search/filter strings enter SQLite storage and
   parameterized queries.
3. **Browser / Loopback HTTP Boundary (`dashboard.py` <-> `static/app.js`):**
   Local browser requests over loopback (`127.0.0.1` / `localhost` / `::1`) against
   potential cross-site requests, DNS rebinding, path traversal, or DOM XSS.
4. **Exported HTML Report (`report.py`):**
   Self-contained HTML opened in a browser where packet-derived strings must remain inert.

## 3. Threat Analysis and Mitigations

| Threat | Mechanism / Mitigation | Verification |
|---|---|---|
| Malformed/oversized PCAP exhaustion or crash | `PcapReader` validates magic, version 2.4, supported linktypes, timestamp fractions, `incl_len <= orig_len`, and `incl_len <= snaplen` before reading payloads; `parse_packet` catches malformed packets; `HostTable`, `Engine.talkers`, detectors, and `Store._queue` are strictly bounded. | `tests/test_pcap_and_parsers.py`, `tests/test_reliability.py` |
| Stored/reflected XSS in dashboard UI | `app.js` uses `textContent` / `document.createElement` (no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, or `eval`), plus HTTP `Content-Security-Policy` (`default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`) and `X-Content-Type-Options: nosniff`. | `tests/test_dashboard.py`, `tests/test_security.py` |
| XSS / script execution in standalone HTML reports | `report.py` HTML-escapes every interpolated field with `html.escape(..., quote=True)` and embeds `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'">`. | `tests/test_dashboard.py`, `tests/test_security.py` |
| DNS rebinding / Host-header / CSRF attacks | `Handler._host_allowed()` allows only `localhost`, `127.0.0.1`, `::1` matching the bound port; `do_POST` verifies loopback `Origin` (when sent) and constant-time `hmac.compare_digest` on `X-PacketLens-Token`; `X-Frame-Options: DENY` and `frame-ancestors 'none'` prevent framing. | `tests/test_dashboard.py`, `tests/test_security.py` |
| Token caching in browser or logs | `GET /` and `GET /index.html` emit `Cache-Control: no-store`; `serve()` does not emit the token to Python `logging`. | `tests/test_security.py` |
| Path traversal / symlink escape on `/api/quality/<name>` | Rejects `/`, `\`, `%`, non-`.json` names, symlinks (`is_symlink()`), and files whose `resolve().parent` differs from `results_path.resolve()`; enforces `1 MiB` read cap and rejects `NaN`/`Infinity`. | `tests/test_dashboard.py`, `tests/test_security.py` |
| SQL injection in filters / search / sorting | All SQLite values use `?` placeholders; `LIKE` wildcards are escaped via `_escape_like`; `ORDER BY` uses an explicit `sort_columns` allowlist; query parameters reject duplicates and oversized lengths. | `tests/test_policy_store_engine.py`, `tests/test_security.py` |
| Accidental unencrypted network exposure | `serve()` defaults to `127.0.0.1` and raises `ValueError` for non-loopback `--host` unless `--allow-remote` (`allow_non_loopback=True`) is explicitly supplied. | `tests/test_security.py` |
| Excessive request body / DoS | `do_POST` requires `Content-Type: application/json`, strict `Content-Length` in `[0, 1 MiB]`, exact key set `{"status", "note"}`, and `len(note) <= 4000`. | `tests/test_dashboard.py`, `tests/test_security.py` |

## 4. Privilege Boundaries and Data Handling

- Offline PCAP analysis and loopback `serve` run under the unprivileged Windows 11 user
  account; no Administrator elevation or raw socket privilege is required.
- File-system confidentiality of `packetlens.db`, captures, and HTML reports relies on
  Windows 11 user profile NTFS permissions (operators must store captures and databases
  only in user-private directories).
- Retention pruning (`packetlens store prune --db ... --days 90`) removes closed records
  older than 90 days while retaining open/acknowledged incidents for triage.

## 5. Residual Risks (For Human Reviewer / Maintainer Decision)

1. **No TLS on built-in HTTP server:** Even with `--allow-remote`, traffic is plaintext
   HTTP. Remote exposure remains unapproved without an authenticated TLS reverse proxy.
2. **Token printed to terminal stdout:** Anyone with access to the user's terminal
   scrollback or local process session while `serve` runs can read the token.
3. **Unencrypted SQLite at rest:** `packetlens.db` stores incident summaries and host IPs
   in plaintext SQLite; BitLocker / NTFS ACLs are relied upon on Windows 11.
4. **No multi-user RBAC / audit attribution:** Status changes in `audit_log` do not record
   a username because the deployment assumes a single local operator.
