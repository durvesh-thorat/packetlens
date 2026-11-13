# PacketLens Operations, Observability, and Recovery Runbook

This runbook covers day-to-day operation, health diagnostics, incident triage, rollback,
and shutdown procedures for PacketLens in its M0 target environment (one Windows 11
workstation running offline classic-PCAP analysis and loopback dashboard replay).

---

## 1. Prerequisites and Installation

### 1.1 System Requirements
- **Operating System:** Windows 11 (64-bit).
- **Python Runtime:** Python 3.10 or newer (validated on Python 3.12.10 on Windows 11).
- **Hardware Profile:** 4 CPU cores, 8 GB RAM minimum, SSD storage recommended for large PCAP analysis.
- **Dependencies:** Core engine uses Python standard library only (`sqlite3`, `http.server`, `socket`, `struct`, `json`, `dataclasses`, `argparse`). Zero external pip packages required for core analysis and dashboard.
- **Optional Tools:**
  - `Wireshark` / `tshark` (version 4.0+) for PCAP conversion (`editcap -F pcap in.pcapng out.pcap`) and independent capture validation.
  - `Node.js` (v18+) for static asset syntax verification (`node --check packetlens/static/app.js`).

### 1.2 Virtual Environment Setup and Installation
Open PowerShell on the Windows 11 workstation:

```powershell
# Navigate to project directory
cd C:\packetlens

# Create an isolated virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install PacketLens in editable mode (standard library only)
python -m pip install -e .

# Run test suite to verify installation
python -m unittest discover -s tests -v
```

### 1.3 CLI Command Verification
Verify that all core CLI entry points are accessible:

```powershell
python -m packetlens --help
python -m packetlens analyze --help
python -m packetlens serve --help
python -m packetlens report --help
python -m packetlens store --help
python -m packetlens evaluate --help
python -m packetlens incidents --help
```

---

## 2. Standard Offline and Pilot Workflows

### 2.1 Batch PCAP Analysis
Analyze a classic PCAP capture (`version 2.4`, Ethernet linktype `1` or Linux cooked linktype `113`):

```powershell
# Ingest and analyze capture into local SQLite store
python -m packetlens analyze C:\captures\pilot_day1.pcap --db packetlens.db

# Ingest with a specific policy file
python -m packetlens analyze C:\captures\pilot_day1.pcap --db packetlens.db --policy packetlens/policies/default.json
```

*Note on PCAP formats:* PacketLens strictly parses classic PCAP v2.4 files. If input files are in `pcapng` format (magic `0x0a0d0d0a`), convert them prior to ingestion:
```powershell
editcap -F pcap input.pcapng output.pcap
```

### 2.2 Loopback Web Console Replay
Launch the local loopback web console for interactive incident investigation and replay:

```powershell
python -m packetlens serve --pcap C:\captures\pilot_day1.pcap --db packetlens.db --port 8000 --loop
```

- **Loopback Boundary:** The dashboard binds strictly to `127.0.0.1` by default. Remote binding is disabled unless `--allow-remote` is explicitly specified.
- **Access Token:** On launch, a cryptographically secure one-time token is generated and printed to stdout. Save this token: it is required for all incident status mutations (`ack` and `close`).

### 2.3 Standalone HTML Report Generation
Export an offline, self-contained HTML report locked with `script-src 'none'` Content Security Policy:

```powershell
python -m packetlens report --db packetlens.db --out reports\pilot_day1_report.html
```

---

## 3. Observability and Health Monitoring

### 3.1 Health Endpoint (`GET /api/health`)
The dashboard exposes a JSON health status endpoint at `http://127.0.0.1:8000/api/health`.

Example healthy response:
```json
{
  "service_status": "healthy",
  "degraded_reasons": [],
  "memory_rss_bytes": 52428800,
  "avg_processing_us": 14.2,
  "max_processing_us": 85.0,
  "store_counters": {
    "queued": 0,
    "queue_capacity": 10000,
    "written": 45000,
    "dropped": 0,
    "writer_alive": true,
    "writer_error": null,
    "status": "healthy"
  }
}
```

### 3.2 Health Indicator States
The dashboard topbar displays real-time health indicators reflecting `service_status`:
- **`healthy` (Green):** Engine is processing packets normally, SQLite writer thread is alive, queue depth is nominal (< 8,000 items), and no drop counters have incremented.
- **`degraded` (Amber):** One or more non-fatal warning conditions have triggered (see diagnostic table below). The topbar displays active reason codes.
- **`unhealthy` (Red):** Critical failure in storage writer or packet source that prevents reliable recording or analysis.

### 3.3 Diagnostic Runbook for Degraded Conditions

| Degraded Reason | Cause | Impact | Operator Action |
|---|---|---|---|
| `source_stale` | No packet ingested for >= 10.0 seconds during active replay. | Replay may have completed or input feed stalled. | If replaying a finite PCAP without `--loop`, this is expected upon completion. If `--loop` was requested or feed should be active, verify file read permissions and disk responsiveness. |
| `source_error` | Unhandled exception encountered by the packet source generator. | Packet ingestion has stopped. | Check terminal output for stack trace. Inspect capture file for file truncation, corrupted headers, or non-supported linktypes using `tshark -r <file>`. |
| `store_drops` | Asynchronous SQLite queue exceeded `QUEUE_CAPACITY` (10,000 items); incoming records dropped. | Loss of packet statistics or alert records in database. | System I/O cannot keep up with replay speed. Switch to offline batch analysis (`packetlens analyze`), which has no wall-clock replay deadline, or split oversized captures into smaller chunks. |
| `store_writer_error` | Background SQLite writer thread failed with an exception. | Database writes halted; engine health becomes `unhealthy`. | Inspect `store_error` in `/api/health`. Check Windows disk space (`wmic logicaldisk get size,freespace,caption`), verify SQLite file permissions, and ensure no other process has locked `packetlens.db`. Restart process. |

### 3.4 Process Memory Monitoring (Win32 RSS)
PacketLens tracks resident set memory on Windows via standard Win32 process memory queries.
- **Baseline Memory:** Typically 35 MB to 75 MB working set under normal pilot operation.
- **Threshold Limit:** 150 MB RSS.
- **Remediation if RSS > 150 MB:** If memory approaches 150 MB, check incident count in `packetlens.db` and prune closed incidents older than 30 days. If memory continues to grow, verify flow table cardinality in custom rules.

---

## 4. Incident Triage Standard Operating Procedure (SOP)

Operator triage must be efficient, reproducible, and verifiable. The target operational SLA is **< 3 minutes per incident**.

```
[Alert Ingested] ──> [List Open Incidents] ──> [Inspect Evidence] ──> [Determine Nature]
                                                                             │
                     ┌───────────────────────────────────────────────────────┴────────────────────────────────────────┐
                     ▼                                                                                                ▼
           [True Positive (Attack)]                                                                       [False Positive / Benign]
                     │                                                                                                │
  1. Acknowledge: `packetlens incidents ack <id>`                                                  1. Acknowledge: `packetlens incidents ack <id>`
  2. Export evidence: `packetlens report`                                                         2. Close: `packetlens incidents close <id> --reason "false_positive"`
  3. Notify incident response team                                                                 3. Log rule name & flow pattern for policy tuning
  4. Close: `packetlens incidents close <id> --reason "true_positive"`
```

### Step 1: Discover Active Incidents
Query all open incidents using the CLI or the loopback web console (`http://127.0.0.1:8000/`):

```powershell
python -m packetlens incidents list --db packetlens.db --status open
```

### Step 2: Inspect Incident Evidence
Examine incident metadata, correlated alerts, involved flow tuples, and timing:

```powershell
python -m packetlens incidents show <incident_id> --db packetlens.db
```

Review:
- **Rule Name:** e.g., `port-scan`, `syn-flood`, `arp-spoof`, `dns-tunnel`, `horizontal-scan`.
- **Source & Destination IPs:** Determine whether endpoints are legitimate internal assets, DNS resolvers, or external hosts.
- **Packet & Byte Counts:** Rapid burst vs sustained low-rate activity.
- **Correlated Alerts:** Check whether multiple signature rules fired on the same host.

### Step 3: Classification and Action

#### Case A: True Positive / Confirmed Malicious Activity
1. **Acknowledge incident immediately:**
   ```powershell
   python -m packetlens incidents ack <incident_id> --db packetlens.db --token <auth_token>
   ```
2. **Export self-contained forensic HTML report:**
   ```powershell
   python -m packetlens report --db packetlens.db --out reports\incident_<incident_id>.html
   ```
3. **Escalate to security operations:** Attach the exported HTML report and flow details.
4. **Close incident upon containment:**
   ```powershell
   python -m packetlens incidents close <incident_id> --db packetlens.db --token <auth_token>
   ```

#### Case B: False Alarm / Authorized Administrative Traffic
1. **Acknowledge incident:**
   ```powershell
   python -m packetlens incidents ack <incident_id> --db packetlens.db --token <auth_token>
   ```
2. **Close incident with clear audit rationale:**
   ```powershell
   python -m packetlens incidents close <incident_id> --db packetlens.db --token <auth_token>
   ```
3. **Policy Review:** If a rule repeatedly triggers on known benign traffic (e.g. vulnerability scanner), consider adding IP exclusions or adjusting rule sensitivity in `packetlens/policies/default.json`.

---

## 5. Backup, Retention, and Recovery

### 5.1 WAL-Safe Online/Offline Backup
Never copy an active `packetlens.db` file directly with `copy` or `xcopy`, as the SQLite Write-Ahead Log (`-wal`) and shared memory (`-shm`) sidecar files will cause database corruption if copied mid-transaction. Always use `packetlens store backup`:

```powershell
python -m packetlens store backup --db packetlens.db --out backups\packetlens_backup.db
```

### 5.2 Backup Integrity Verification
Verify database integrity on the backup copy:

```powershell
python -c "import sqlite3; c = sqlite3.connect('backups/packetlens_backup.db'); print('Integrity:', c.execute('PRAGMA integrity_check').fetchone()[0])"
```

### 5.3 Database Restore Procedure
1. Stop any running `packetlens serve` or `packetlens analyze` process.
2. Archive the damaged database files:
   ```powershell
   Move-Item packetlens.db packetlens.db.damaged -Force
   if (Test-Path packetlens.db-wal) { Move-Item packetlens.db-wal packetlens.db-wal.damaged -Force }
   if (Test-Path packetlens.db-shm) { Move-Item packetlens.db-shm packetlens.db-shm.damaged -Force }
   ```
3. Copy the verified backup to active location:
   ```powershell
   Copy-Item backups\packetlens_backup.db packetlens.db
   ```
4. Confirm database readability:
   ```powershell
   python -m packetlens incidents list --db packetlens.db
   ```

### 5.4 30-Day Retention Pruning
Per M0 policy, closed incidents, resolved alerts, minute metrics, and capture runs older than 30 days must be pruned periodically to prevent unbounded disk growth. Active (`open` and `acknowledged`) incidents are strictly preserved:

```powershell
python -m packetlens store prune --db packetlens.db --days 30
```

---

## 6. Safe Rollback Runbook

If a software defect, policy misconfiguration, or unexpected behavior is detected during pilot operations, follow this rollback procedure.

### 6.1 Code Rollback
1. Stop running processes (`Ctrl+C` or task termination).
2. Check out the previous stable git release tag or commit hash:
   ```powershell
   git checkout tags/vX.Y.Z
   # or
   git checkout <stable_commit_hash>
   ```
3. Reinstall editable package:
   ```powershell
   python -m pip install -e .
   ```
4. Verify regression suite:
   ```powershell
   python -m unittest discover -s tests -v
   ```

### 6.2 Detection Policy Rollback
If a policy change introduced excessive false positives or broke detection rules:
1. Revert `packetlens/policies/default.json` to the last known good configuration:
   ```powershell
   git checkout HEAD -- packetlens/policies/default.json
   ```
2. Verify policy syntax and rule schema validity:
   ```powershell
   python -m unittest tests/test_rules.py
   ```

### 6.3 Database Backward Compatibility & Audit Preservation
- **Schema Compatibility:** The PacketLens SQLite schema is append-only and backward compatible across minor versions.
- **Audit Preservation:** **NEVER** delete `packetlens.db` during a rollback. Historical incident audit entries, operator acknowledgments, and timestamps must be retained for compliance.
- If a database rollback is required due to corruption, restore from the last verified backup per Section 5.3.

---

## 7. Graceful and Emergency Shutdown Runbook

### 7.1 Graceful Shutdown (Standard Procedure)
When stopping `packetlens serve`:
1. Press `Ctrl+C` in the running PowerShell terminal window.
2. The process intercepts the `SIGINT` signal, initiates graceful queue drain (`store.flush()`), commits all pending SQLite transactions, shuts down the HTTP server cleanly, and exits with code 0.
3. Verification: Check terminal output for clean exit message:
   ```
   Shutting down dashboard server...
   Flushing store queue...
   Store closed cleanly.
   ```

### 7.2 Emergency Shutdown (Process Hang or System Starvation)
If the process becomes completely unresponsive due to resource exhaustion or external system deadlock:
1. Identify the running process ID:
   ```powershell
   Get-Process -Name python | Where-Object { $_.CommandLine -like "*packetlens*" }
   ```
2. Forcefully terminate the process:
   ```powershell
   Stop-Process -Id <PID> -Force
   # or via cmd:
   taskkill /PID <PID> /F
   ```
3. Post-Emergency Recovery:
   - SQLite WAL mode ensures transactional ACID properties; committed transactions remain intact.
   - Run integrity check before restarting:
     ```powershell
     python -c "import sqlite3; c = sqlite3.connect('packetlens.db'); print(c.execute('PRAGMA integrity_check').fetchone()[0])"
     ```
   - Restart `packetlens serve` or `packetlens analyze`.
