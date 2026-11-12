# PacketLens Operations, Observability, and Recovery Runbook

This runbook covers day-to-day operation of PacketLens in its M0 target environment
(one Windows 11 workstation running offline classic-PCAP analysis and loopback
dashboard replay).

## 1. Prerequisites and Installation

- Python 3.10 or newer (validated on Python 3.12.10 on Windows 11)
- Core installation (standard library only):

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
```

- Optional JavaScript syntax check (requires Node.js):

```powershell
node --check packetlens/static/app.js
```

## 2. Standard Offline Workflows

1. **Analyze a classic PCAP file (`version 2.4`, Ethernet `1` or Linux cooked `113`):**
   Convert `pcapng` inputs externally first (`editcap -F pcap in.pcapng out.pcap`).

   ```powershell
   python -m packetlens analyze capture.pcap --db packetlens.db
   ```

2. **Launch the loopback dashboard (`127.0.0.1` only):**

   ```powershell
   python -m packetlens serve --pcap capture.pcap --db packetlens.db --loop
   ```

   Record the one-time access token printed to stdout; it is required for incident
   status transitions (`ack` / `close`).

3. **Export a self-contained HTML report:**

   ```powershell
   python -m packetlens report --db packetlens.db --out report.html
   ```

## 3. Observability and Health Monitoring

Inspect `GET /api/health` (or the topbar health indicator in the dashboard):

- `service_status`: `"healthy"`, `"degraded"`, or `"unhealthy"`.
- `degraded_reasons`: list of active conditions:
  - `source_stale`: no packet received for at least `10.0` seconds.
  - `source_error`: packet source stopped with an exception (`source_error` contains detail).
  - `store_drops`: asynchronous SQLite writer queue (`QUEUE_CAPACITY = 10,000`) dropped writes.
  - `store_writer_error`: SQLite background writer failed (`store_error` contains detail).
- `memory_rss_bytes`: current process working set / resident memory in bytes.
- `avg_processing_us`, `max_processing_us`: per-packet engine processing latency in microseconds.
- `store_counters`: `queued`, `queue_capacity`, `written`, `dropped`, `writer_alive`, `writer_error`, `status`.

When `service_status` is `"degraded"` or `"unhealthy"`, the dashboard displays the
status banner with the active reason codes rather than reporting `"Connected"`.

Structured logs are emitted via Python's standard `logging` module from
`packetlens.engine`, `packetlens.store`, and `packetlens.dashboard`.

## 4. Backup, Retention, and Recovery

### WAL-Safe Online/Offline Backup

Always use `packetlens store backup` (backed by `sqlite3.Connection.backup`) rather
than copying `.db` without its `-wal` / `-shm` sidecar files:

```powershell
python -m packetlens store backup --db packetlens.db --out backups\packetlens-backup.db
```

Verify backup integrity:

```powershell
python -c "import sqlite3; c=sqlite3.connect('backups/packetlens-backup.db'); print(c.execute('PRAGMA integrity_check').fetchone()[0])"
```

### Restore Procedure

1. Stop any running `packetlens serve` process (`Ctrl-C` waits for graceful drain and
   `Store.close()`).
2. Move or archive the damaged `packetlens.db`, `packetlens.db-wal`, and `packetlens.db-shm`.
3. Copy the verified backup file to `packetlens.db`.
4. Verify with `python -m packetlens incidents list --db packetlens.db`.

### 90-Day Retention Pruning

Per M0 policy, closed incidents, their alerts/audit entries, `minute_stats`, and
`capture_runs` older than 90 days can be pruned while keeping `open` and `acknowledged`
incidents intact:

```powershell
python -m packetlens store prune --db packetlens.db --days 90
```

## 5. Failure Handling

- **Disk full or SQLite I/O failure (`store_writer_error`):** Stop ingestion, free disk
  space or verify filesystem permissions, back up or inspect the last good database copy,
  and restart the process so a fresh `Store` writer thread starts cleanly.
- **Queue drops (`store_drops`):** Re-run offline PCAP analysis with `packetlens analyze`
  (no wall-clock replay deadline) or split captures larger than 2 GB before replay.
- **Stale source (`source_stale` / `source_error`):** Check the input PCAP integrity or
  restart `serve` without `--loop` if one-shot replay completed as expected.
