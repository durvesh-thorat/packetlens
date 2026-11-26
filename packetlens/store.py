"""SQLite-backed incident, host, and traffic-stat storage.

Writes are handled by one daemon thread and a bounded queue (10,000 jobs); if the
queue is full, submissions are dropped and counted. Read results are capped to keep
large stores from causing unbounded response memory.
"""
import json
import logging
import math
import os
import queue
import random
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path

logger = logging.getLogger(__name__)


QUEUE_CAPACITY = 10000
MAX_PAGE_SIZE = 500
MAX_INCIDENT_ALERTS = 1000
MAX_INCIDENT_AUDIT = 200
MAX_MINUTE_STATS = 10000
MAX_HOST_PEERS = 2000
MAX_ACTIVE_GROUPS = 50000
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_SORT_COLUMNS = {
    "last_ts": "last_ts",
    "first_ts": "first_ts",
    "count": "count",
    "severity": ("CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                 "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"),
    "status": "status",
    "kind": "kind",
    "src": "src",
}


def _is_transient_sqlite_error(exc):
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    msg = str(exc).lower()
    return "locked" in msg or "busy" in msg


def migrate(connection):
    """Create or upgrade the SQLite schema."""
    connection.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if row is None:
        connection.execute("INSERT INTO schema_version(version) VALUES (0)")
        version = 0
    else:
        version = row[0]
    if version < 1:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, src TEXT NOT NULL,
                status TEXT NOT NULL, severity TEXT NOT NULL, count INTEGER NOT NULL,
                first_ts REAL NOT NULL, last_ts REAL NOT NULL, detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT,
                ts REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
                src TEXT NOT NULL, dst TEXT NOT NULL, detail TEXT NOT NULL,
                policy_id TEXT NOT NULL, data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alerts_incident_idx ON alerts(incident_id, ts);
            CREATE INDEX IF NOT EXISTS alerts_kind_src_idx ON alerts(kind, src, ts);
            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                packets_in INTEGER NOT NULL, packets_out INTEGER NOT NULL,
                bytes_in INTEGER NOT NULL, bytes_out INTEGER NOT NULL,
                peers_json TEXT NOT NULL, peers_truncated INTEGER NOT NULL,
                top_ports_json TEXT NOT NULL, protocols_json TEXT NOT NULL,
                alert_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS minute_stats (
                t REAL PRIMARY KEY, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
                syn INTEGER NOT NULL, dns INTEGER NOT NULL, sources INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
                ts REAL NOT NULL, action TEXT NOT NULL, note TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_incident_idx ON audit_log(incident_id, id);
        """)
        connection.execute("UPDATE schema_version SET version = 1")
        version = 1
    if version < 2:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS capture_runs (
                id TEXT PRIMARY KEY, source TEXT NOT NULL, packets INTEGER NOT NULL,
                bytes INTEGER NOT NULL, malformed INTEGER NOT NULL,
                first_ts REAL, last_ts REAL
            );
            CREATE INDEX IF NOT EXISTS capture_runs_period_idx ON capture_runs(first_ts,last_ts);
        """)
        connection.execute("UPDATE schema_version SET version = 2")
        version = 2
    if version < 3:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(capture_runs)")}
        if "dropped_writes" not in columns:
            connection.execute("ALTER TABLE capture_runs ADD COLUMN dropped_writes INTEGER NOT NULL DEFAULT 0")
        connection.execute("UPDATE schema_version SET version = 3")
    connection.commit()


class Store:
    """Persistent SQLite store with a single bounded asynchronous writer."""

    def __init__(self, path, queue_capacity=QUEUE_CAPACITY):
        self.path = str(path)
        self.incident_gap_s = 300
        self.queue_capacity = max(1, int(queue_capacity))
        self._queue = queue.Queue(maxsize=self.queue_capacity)
        self._counter_lock = threading.Lock()
        self._incident_lock = threading.Lock()
        self._dropped = 0
        self._written = 0
        self._writer_error = None
        self._closed = False
        setup = sqlite3.connect(self.path, timeout=30)
        try:
            setup.execute("PRAGMA journal_mode=WAL")
            setup.execute("PRAGMA synchronous=NORMAL")
            migrate(setup)
            self._active = OrderedDict()
            for row in setup.execute(
                    "SELECT id,kind,src,status,last_ts,count,first_ts,severity "
                    "FROM incidents WHERE status != 'closed' ORDER BY last_ts"):
                key = (row[1], row[2])
                previous = self._active.get(key)
                if previous is None or row[4] > previous["last_ts"]:
                    self._active[key] = {
                        "id": row[0], "status": row[3], "last_ts": row[4],
                        "count": row[5], "first_ts": row[6], "severity": row[7],
                        "incident_gap_s": 15 if row[1] == "volumetric" else self.incident_gap_s,
                    }
        finally:
            setup.close()
        self._thread = threading.Thread(target=self._writer, name="packetlens-sqlite-writer", daemon=True)
        self._thread.start()

    def _writer(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        max_attempts = 4
        while True:
            job = self._queue.get()
            if job is None:
                self._queue.task_done()
                break
            function, future = job
            try:
                for attempt in range(max_attempts):
                    try:
                        result = function(connection)
                        connection.commit()
                        with self._counter_lock:
                            self._written += 1
                        if future is not None:
                            future["result"] = result
                        break
                    except Exception as exc:
                        connection.rollback()
                        if _is_transient_sqlite_error(exc) and attempt + 1 < max_attempts:
                            delay = 0.02 * (2 ** attempt) + random.uniform(0.0, 0.01)
                            logger.warning("Transient SQLite busy/locked (%s); retrying in %.3fs", exc, delay)
                            time.sleep(delay)
                            continue
                        if not isinstance(exc, ValueError):
                            logger.exception("SQLite writer failed")
                        if future is not None:
                            future["error"] = exc
                        else:
                            with self._counter_lock:
                                self._writer_error = exc
                        break
            finally:
                if future is not None:
                    future["event"].set()
                self._queue.task_done()
        connection.close()

    def _raise_writer_error(self):
        with self._counter_lock:
            err = self._writer_error
        if err is not None:
            raise RuntimeError(f"SQLite writer failed: {err}") from err

    def _enqueue(self, function, wait=False):
        self._raise_writer_error()
        future = {"event": threading.Event(), "result": None, "error": None} if wait else None
        try:
            if wait:
                self._queue.put((function, future))
            else:
                self._queue.put_nowait((function, future))
        except queue.Full:
            with self._counter_lock:
                self._dropped += 1
                dropped = self._dropped
            if dropped == 1 or dropped % 1000 == 0:
                logger.warning("SQLite write queue full (capacity=%d); dropped=%d",
                               self.queue_capacity, dropped)
            return None
        if future is not None:
            future["event"].wait()
            if future["error"] is not None:
                if isinstance(future["error"], ValueError):
                    raise future["error"]
                raise RuntimeError(f"SQLite writer failed: {future['error']}") from future["error"]
            return future["result"]
        return True

    def add_alert(self, alert):
        """Store an alert and return its grouped incident id, or None for log-only alerts."""
        action = getattr(alert, "_action", "alert")
        values = alert.to_dict() if hasattr(alert, "to_dict") else dict(alert)
        data = values.get("data") or {}
        data_json = json.dumps(data, separators=(",", ":"), allow_nan=False)
        timestamp = float(values["ts"])
        kind, src = str(values["kind"]), str(values["src"])
        severity = str(values["severity"])
        policy_gap = getattr(alert, "_incident_gap_s", None)
        if policy_gap is not None:
            incident_gap_s = float(policy_gap)
        elif kind == "volumetric" and not getattr(alert, "_policy_applied", False):
            incident_gap_s = 15
        else:
            incident_gap_s = self.incident_gap_s
        log_only = action == "log"
        incident_id = None
        if not log_only:
            key = (kind, src)
            with self._incident_lock:
                for active_key, active in list(self._active.items()):
                    active_gap = active.get(
                        "incident_gap_s",
                        15 if active_key[0] == "volumetric" else self.incident_gap_s)
                    if (active["status"] == "closed" or
                            timestamp - active["last_ts"] > active_gap):
                        self._active.pop(active_key)
                current = self._active.get(key)
                if current is None or current["status"] == "closed" or abs(
                        timestamp - current["last_ts"]) > incident_gap_s:
                    self._active.pop(key, None)
                    if len(self._active) >= MAX_ACTIVE_GROUPS:
                        self._active.popitem(last=False)
                    incident_id = uuid.uuid4().hex
                    current = {"id": incident_id, "status": "open", "last_ts": timestamp,
                               "first_ts": timestamp, "count": 0, "severity": severity,
                               "incident_gap_s": incident_gap_s}
                    self._active[key] = current
                else:
                    incident_id = current["id"]
                    current["first_ts"] = min(current.get("first_ts", timestamp), timestamp)
                    current["last_ts"] = max(current["last_ts"], timestamp)
                    current["count"] = current.get("count", 0) + 1
                    current["incident_gap_s"] = incident_gap_s
                    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(current["severity"], 0):
                        current["severity"] = severity
                if current["count"] == 0:
                    current["count"] = 1
                if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(current["severity"], 0):
                    current["severity"] = severity
                self._active.move_to_end(key)
                snapshot = dict(current)

        row = {
            "incident_id": incident_id, "ts": timestamp, "kind": kind, "severity": severity,
            "src": src, "dst": str(values.get("dst", "")), "detail": str(values.get("detail", "")),
            "policy_id": str(values.get("policy_id", "")), "data_json": data_json,
        }

        def write(connection):
            if incident_id is not None:
                connection.execute("""
                    INSERT INTO incidents(id,kind,src,status,severity,count,first_ts,last_ts,detail)
                    VALUES(?,?,?,'open',?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        severity=excluded.severity, count=excluded.count,
                        first_ts=excluded.first_ts, last_ts=excluded.last_ts, detail=excluded.detail
                """, (incident_id, kind, src, snapshot["severity"], snapshot["count"],
                      snapshot["first_ts"], snapshot["last_ts"], row["detail"]))
            connection.execute("""
                INSERT INTO alerts(incident_id,ts,kind,severity,src,dst,detail,policy_id,data_json)
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (row["incident_id"], row["ts"], row["kind"], row["severity"], row["src"],
                  row["dst"], row["detail"], row["policy_id"], row["data_json"]))
        accepted = self._enqueue(write)
        if accepted is None and incident_id is not None:
            return incident_id
        return incident_id

    def upsert_hosts(self, list_of_dicts):
        """Queue profile snapshots; host records and peer arrays are bounded."""
        rows = []
        for value in list_of_dicts:
            if not isinstance(value, dict) or not isinstance(value.get("ip"), str):
                continue
            peers = value.get("peers", [])
            if not isinstance(peers, list):
                peers = []
            peers = list(dict.fromkeys(str(peer) for peer in peers))[:MAX_HOST_PEERS]
            rows.append({
                "ip": value["ip"], "first_seen": float(value.get("first_seen", 0)),
                "last_seen": float(value.get("last_seen", 0)),
                "packets_in": max(0, int(value.get("packets_in", 0))),
                "packets_out": max(0, int(value.get("packets_out", 0))),
                "bytes_in": max(0, int(value.get("bytes_in", 0))),
                "bytes_out": max(0, int(value.get("bytes_out", 0))),
                "peers": peers, "peers_truncated": bool(value.get("peers_truncated", False)),
                "top_ports": value.get("top_ports", [])[:10],
                "protocols": value.get("protocols", {}),
                "alert_count": max(0, int(value.get("alert_count", 0))),
            })

        def write(connection):
            existing = {}
            ips = [row["ip"] for row in rows]
            for start in range(0, len(ips), 500):
                chunk = ips[start:start + 500]
                placeholders = ",".join("?" * len(chunk))
                for old_row in connection.execute(
                    f"SELECT ip,peers_json,top_ports_json,protocols_json FROM hosts WHERE ip IN ({placeholders})",
                    chunk,
                ):
                    existing[old_row[0]] = (
                        json.loads(old_row[1]),
                        json.loads(old_row[2]),
                        json.loads(old_row[3]),
                    )
            params = []
            for row in rows:
                peers = row["peers"]
                ports = row["top_ports"]
                protocols = row["protocols"]
                old = existing.get(row["ip"])
                if old is not None:
                    old_peers, old_ports, old_protocols = old
                    peers = list(dict.fromkeys(old_peers + peers))[:MAX_HOST_PEERS]
                    port_counts = {str(port): count for port, count in old_ports}
                    for port, count in ports:
                        port_counts[str(port)] = max(int(count), int(port_counts.get(str(port), 0)))
                    ports = [[int(port), count] for port, count in
                             sorted(port_counts.items(), key=lambda item: int(item[1]), reverse=True)[:10]]
                    merged_protocols = dict(old_protocols)
                    for protocol, count in protocols.items():
                        merged_protocols[protocol] = max(int(count), int(merged_protocols.get(protocol, 0)))
                    protocols = merged_protocols
                existing[row["ip"]] = (peers, ports, protocols)
                params.append((
                    row["ip"], row["first_seen"], row["last_seen"], row["packets_in"],
                    row["packets_out"], row["bytes_in"], row["bytes_out"], json.dumps(peers),
                    int(row["peers_truncated"]), json.dumps(ports), json.dumps(protocols),
                    row["alert_count"],
                ))
            connection.executemany("""
                INSERT INTO hosts(ip,first_seen,last_seen,packets_in,packets_out,bytes_in,bytes_out,
                    peers_json,peers_truncated,top_ports_json,protocols_json,alert_count)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    first_seen=min(hosts.first_seen,excluded.first_seen),
                    last_seen=max(hosts.last_seen,excluded.last_seen),
                    packets_in=max(hosts.packets_in,excluded.packets_in),
                    packets_out=max(hosts.packets_out,excluded.packets_out),
                    bytes_in=max(hosts.bytes_in,excluded.bytes_in),
                    bytes_out=max(hosts.bytes_out,excluded.bytes_out),
                    peers_json=excluded.peers_json,
                    peers_truncated=max(hosts.peers_truncated,excluded.peers_truncated),
                    top_ports_json=excluded.top_ports_json,
                    protocols_json=excluded.protocols_json,
                    alert_count=max(hosts.alert_count,excluded.alert_count)
            """, params)
        if rows:
            return self._enqueue(write)
        return True

    def add_minute_stat(self, bin_dict):
        """Queue one bounded-size traffic bin, replacing a duplicate timestamp."""
        row = (float(bin_dict["t"]), int(bin_dict["packets"]), int(bin_dict["bytes"]),
               int(bin_dict["syn"]), int(bin_dict["dns"]), int(bin_dict["sources"]))
        self._enqueue(lambda connection: connection.execute(
            "INSERT INTO minute_stats(t,packets,bytes,syn,dns,sources) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(t) DO UPDATE SET packets=excluded.packets,bytes=excluded.bytes,"
            "syn=excluded.syn,dns=excluded.dns,sources=excluded.sources", row))

    def record_capture(self, source, packets, byte_count, malformed, first_ts=None, last_ts=None,
                       dropped_writes=0):
        """Persist additive per-run traffic totals for later reports."""
        values = (str(source), int(packets), int(byte_count), int(malformed),
                  None if first_ts is None else float(first_ts),
                  None if last_ts is None else float(last_ts), int(dropped_writes))
        if min(values[1:4]) < 0 or values[6] < 0:
            raise ValueError("capture counts must not be negative")
        run_id = uuid.uuid4().hex
        self._enqueue(lambda connection: connection.execute(
            "INSERT INTO capture_runs(id,source,packets,bytes,malformed,first_ts,last_ts,dropped_writes) "
            "VALUES(?,?,?,?,?,?,?,?)", (run_id,) + values), wait=True)

    def capture_summary(self, flush=True):
        """Return persisted packet totals; legacy stores fall back to their traffic bins."""
        if flush:
            self.flush()
        connection = self._connect_read()
        try:
            summary = connection.execute(
                "SELECT count(*) AS runs,coalesce(sum(packets),0) AS packets,"
                "coalesce(sum(bytes),0) AS bytes,coalesce(sum(malformed),0) AS malformed,"
                "min(first_ts) AS first_ts,max(last_ts) AS last_ts,"
                "coalesce(sum(dropped_writes),0) AS dropped_writes FROM capture_runs").fetchone()
            result = dict(summary)
            if result["runs"] == 0:
                bins = connection.execute(
                    "SELECT coalesce(sum(packets),0) AS packets,coalesce(sum(bytes),0) AS bytes,"
                    "min(t) AS first_ts,max(t) AS last_ts FROM minute_stats").fetchone()
                result.update(dict(bins))
                result["malformed"] = None
                result["dropped_writes"] = None
            return result
        finally:
            connection.close()

    def flush(self):
        """Wait for all accepted writes and surface any writer failure."""
        result = self._enqueue(lambda connection: None, wait=True)
        self._raise_writer_error()
        return result

    def close(self):
        """Drain accepted writes and stop the sole writer thread."""
        if not self._thread.is_alive():
            self._closed = True
            return
        flush_error = None
        try:
            self.flush()
        except RuntimeError as exc:
            flush_error = exc
        self._closed = True
        self._queue.put(None)
        self._thread.join()
        if flush_error is not None:
            raise flush_error
        self._raise_writer_error()

    def counters(self):
        """Return the queue's current size, capacity, health, and drop/write counts."""
        with self._counter_lock:
            writer_error = None if self._writer_error is None else str(self._writer_error)
            dropped = self._dropped
            written = self._written
        writer_alive = self._thread.is_alive()
        if writer_error is not None or (not self._closed and not writer_alive):
            status = "error"
        elif dropped > 0:
            status = "degraded"
        else:
            status = "ok"
        return {
            "dropped": dropped,
            "queued": self._queue.qsize(),
            "queue_capacity": self.queue_capacity,
            "written": written,
            "writer_alive": writer_alive,
            "writer_error": writer_error,
            "status": status,
        }

    def backup(self, dest_path):
        """Create a consistent WAL-safe SQLite backup at `dest_path`."""
        dest = Path(dest_path)
        if os.path.abspath(str(dest)) == os.path.abspath(self.path):
            raise ValueError("backup destination must differ from the active database path")
        dest.parent.mkdir(parents=True, exist_ok=True)
        existed_before = dest.exists()
        self.flush()

        def run_backup(connection):
            target = sqlite3.connect(str(dest), timeout=30)
            try:
                connection.backup(target)
            finally:
                target.close()

        try:
            self._enqueue(run_backup, wait=True)
        except Exception:
            if not existed_before and dest.exists():
                try:
                    dest.unlink()
                except OSError:
                    pass
            raise
        logger.info("SQLite store backed up from %s to %s", self.path, dest)
        return str(dest)

    def prune_older_than(self, cutoff_ts):
        """Delete closed/expired records strictly older than `cutoff_ts` while keeping open incidents."""
        cutoff = float(cutoff_ts)
        if not math.isfinite(cutoff):
            raise ValueError("cutoff timestamp must be finite")

        def run_prune(connection):
            expired_ids_sql = "SELECT id FROM incidents WHERE status='closed' AND last_ts < ?"
            alerts_cur = connection.execute(
                f"DELETE FROM alerts WHERE ts < ? AND (incident_id IS NULL OR incident_id IN ({expired_ids_sql}))",
                (cutoff, cutoff),
            )
            audit_cur = connection.execute(
                f"DELETE FROM audit_log WHERE incident_id IN ({expired_ids_sql})",
                (cutoff,),
            )
            incidents_cur = connection.execute(
                "DELETE FROM incidents WHERE status='closed' AND last_ts < ?",
                (cutoff,),
            )
            stats_cur = connection.execute(
                "DELETE FROM minute_stats WHERE t < ?",
                (cutoff,),
            )
            runs_cur = connection.execute(
                "DELETE FROM capture_runs WHERE last_ts IS NOT NULL AND last_ts < ?",
                (cutoff,),
            )
            return {
                "incidents": incidents_cur.rowcount,
                "alerts": alerts_cur.rowcount,
                "audit_log": audit_cur.rowcount,
                "minute_stats": stats_cur.rowcount,
                "capture_runs": runs_cur.rowcount,
            }

        counts = self._enqueue(run_prune, wait=True)
        logger.info("Pruned store %s older than %s: %s", self.path, cutoff, counts)
        return counts

    def _connect_read(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _escape_like(value):
        return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @staticmethod
    def _incident_dict(row):
        return dict(row)

    def list_incidents(self, status=None, severity=None, kind=None, q=None, limit=50, offset=0,
                       sort="last_ts", order="desc"):
        """List at most 500 matching incidents; q treats LIKE wildcards literally."""
        if sort not in INCIDENT_SORT_COLUMNS:
            raise ValueError(f"unsupported incident sort: {sort}")
        direction = str(order).upper()
        if direction not in {"ASC", "DESC"}:
            raise ValueError(f"unsupported sort order: {order}")
        self.flush()
        clauses, params = [], []
        for column, value in (("status", status), ("severity", severity), ("kind", kind)):
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        if q:
            term = f"%{self._escape_like(q)}%"
            clauses.append("(kind LIKE ? ESCAPE '\\' OR src LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')")
            params.extend((term, term, term))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        limit = min(MAX_PAGE_SIZE, max(0, int(limit)))
        offset = max(0, int(offset))
        order_expr = INCIDENT_SORT_COLUMNS[sort]
        connection = self._connect_read()
        try:
            total = connection.execute("SELECT count(*) FROM incidents" + where, params).fetchone()[0]
            rows = connection.execute("SELECT * FROM incidents" + where +
                                      f" ORDER BY {order_expr} {direction},id ASC LIMIT ? OFFSET ?",
                                      params + [limit, offset]).fetchall()
            return {"total": total, "items": [self._incident_dict(row) for row in rows]}
        finally:
            connection.close()

    def get_incident(self, id):
        """Return one incident and up to 1,000 chronological alerts."""
        self.flush()
        connection = self._connect_read()
        try:
            row = connection.execute("SELECT * FROM incidents WHERE id=?", (str(id),)).fetchone()
            if row is None:
                return None
            result = self._incident_dict(row)
            alerts = connection.execute(
                "SELECT id,incident_id,ts,kind,severity,src,dst,detail,policy_id,data_json "
                "FROM alerts WHERE incident_id=? ORDER BY ts,id LIMIT ?",
                (str(id), MAX_INCIDENT_ALERTS + 1)).fetchall()
            result["alerts_truncated"] = len(alerts) > MAX_INCIDENT_ALERTS
            result["alerts"] = []
            for alert in alerts[:MAX_INCIDENT_ALERTS]:
                item = dict(alert)
                item["data"] = json.loads(item.pop("data_json"))
                result["alerts"].append(item)
            audit = connection.execute(
                "SELECT id,incident_id,ts,action,note FROM audit_log "
                "WHERE incident_id=? ORDER BY ts,id LIMIT ?",
                (str(id), MAX_INCIDENT_AUDIT + 1)).fetchall()
            result["audit_truncated"] = len(audit) > MAX_INCIDENT_AUDIT
            result["audit_log"] = [dict(a) for a in audit[:MAX_INCIDENT_AUDIT]]
            return result
        finally:
            connection.close()

    def set_incident_status(self, id, status, note=""):
        """Apply only open->acknowledged, acknowledged->closed, or open->closed."""
        if status not in {"acknowledged", "closed"}:
            raise ValueError(f"invalid target status: {status!r}")
        update_time = time.time()
        note = str(note)
        allowed = {"open": {"acknowledged", "closed"}, "acknowledged": {"closed"}}

        def write(writer):
            row = writer.execute("SELECT status FROM incidents WHERE id=?", (str(id),)).fetchone()
            if row is None:
                raise ValueError(f"incident not found: {id}")
            if status not in allowed.get(row["status"], set()):
                raise ValueError(f"invalid incident status transition: {row['status']} -> {status}")
            writer.execute("UPDATE incidents SET status=? WHERE id=?", (status, str(id)))
            writer.execute("INSERT INTO audit_log(incident_id,ts,action,note) VALUES(?,?,?,?)",
                           (str(id), update_time, status, note))
            return dict(writer.execute("SELECT * FROM incidents WHERE id=?", (str(id),)).fetchone())
        result = self._enqueue(write, wait=True)
        with self._incident_lock:
            for key, current in list(self._active.items()):
                if current["id"] == str(id):
                    if status == "closed":
                        del self._active[key]
                    else:
                        current["status"] = status
        return result

    def list_hosts(self, q=None, sort="bytes", limit=50, offset=0):
        """List at most 500 profiles, ordered by bytes, recency, alerts, or IP."""
        self.flush()
        sort_columns = {"bytes": "(bytes_in+bytes_out)", "last_seen": "last_seen",
                        "alerts": "alert_count", "ip": "ip"}
        if sort not in sort_columns:
            raise ValueError(f"unsupported host sort: {sort}")
        clauses, params = "", []
        if q:
            clauses = " WHERE ip LIKE ? ESCAPE '\\'"
            params.append(f"%{self._escape_like(q)}%")
        limit, offset = min(MAX_PAGE_SIZE, max(0, int(limit))), max(0, int(offset))
        direction = "ASC" if sort == "ip" else "DESC"
        connection = self._connect_read()
        try:
            total = connection.execute("SELECT count(*) FROM hosts" + clauses, params).fetchone()[0]
            rows = connection.execute(
                "SELECT * FROM hosts" + clauses + f" ORDER BY {sort_columns[sort]} {direction},ip ASC "
                "LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["peers"] = json.loads(item.pop("peers_json"))
                item["top_ports"] = json.loads(item.pop("top_ports_json"))
                item["protocols"] = json.loads(item.pop("protocols_json"))
                items.append(item)
            return {"total": total, "items": items}
        finally:
            connection.close()

    def get_host(self, ip):
        """Return one profile and up to 1,000 related incident identifiers."""
        self.flush()
        connection = self._connect_read()
        try:
            row = connection.execute("SELECT * FROM hosts WHERE ip=?", (str(ip),)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["peers"] = json.loads(result.pop("peers_json"))
            result["top_ports"] = json.loads(result.pop("top_ports_json"))
            result["protocols"] = json.loads(result.pop("protocols_json"))
            result["related_incident_ids"] = [r[0] for r in connection.execute(
                "SELECT DISTINCT incident_id FROM alerts WHERE incident_id IS NOT NULL AND "
                "(src=? OR dst=?) ORDER BY incident_id LIMIT ?", (str(ip), str(ip), MAX_INCIDENT_ALERTS))]
            return result
        finally:
            connection.close()

    def minute_stats(self, t0, t1):
        """Return at most 10,000 bins in the inclusive packet-time range."""
        self.flush()
        connection = self._connect_read()
        try:
            rows = connection.execute(
                "SELECT t,packets,bytes,syn,dns,sources FROM minute_stats WHERE t>=? AND t<=? "
                "ORDER BY t LIMIT ?", (float(t0), float(t1), MAX_MINUTE_STATS)).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def time_bounds(self):
        """Return the earliest and latest packet-time in minute_stats, or None."""
        self.flush()
        connection = self._connect_read()
        try:
            row = connection.execute("SELECT min(t), max(t), count(*) FROM minute_stats").fetchone()
            if row and row[0] is not None:
                return {"first_t": float(row[0]), "last_t": float(row[1]), "count": int(row[2])}
            return {"first_t": None, "last_t": None, "count": 0}
        finally:
            connection.close()

    def summary(self, flush=True):
        """Return totals and open-incident counts grouped by severity."""
        if flush:
            self.flush()
        connection = self._connect_read()
        try:
            groups = connection.execute(
                "SELECT severity,count(*) AS count FROM incidents WHERE status='open' GROUP BY severity").fetchall()
            total, first, last = connection.execute(
                "SELECT count(*),min(ts),max(ts) FROM alerts").fetchone()
            return {"open_by_severity": {row["severity"]: row["count"] for row in groups},
                    "total_alerts": total, "first_ts": first, "last_ts": last}
        finally:
            connection.close()
