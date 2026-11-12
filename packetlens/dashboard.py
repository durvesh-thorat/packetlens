"""Loopback HTTP console for PacketLens."""
import hmac
import json
import logging
import math
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


def _process_rss_bytes():
    """Return current resident memory in bytes using standard-library OS hooks, or None."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            kernel32 = ctypes.windll.kernel32
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            handle = kernel32.GetCurrentProcess()
            get_mem = getattr(kernel32, "K32GetProcessMemoryInfo", None)
            if get_mem is None:
                get_mem = ctypes.windll.psapi.GetProcessMemoryInfo
            get_mem.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            get_mem.restype = wintypes.BOOL
            if get_mem(handle, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
        except Exception:
            return None
        return None
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(rss if sys.platform == "darwin" else rss * 1024)
    except Exception:
        return None

from . import __version__
from .policy import effective_policy
from .store import MAX_PAGE_SIZE, Store

STATIC_DIR = Path(__file__).parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"open", "acknowledged", "closed"}
MAX_BODY = 1024 * 1024
MAX_OFFSET = 10_000_000
SOURCE_STALE_AFTER_S = 10.0
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
       "img-src 'self' data:; connect-src 'self'")


class SourceHealth:
    """Track packet-source receipt times and errors independently of capture timestamps."""

    def __init__(self, engine, started_at, stale_after_s=SOURCE_STALE_AFTER_S):
        self.lock = threading.Lock()
        self.started_at = started_at
        self.stale_after_s = stale_after_s
        snapshot = engine.snapshot()
        self.last_packet_monotonic = time.monotonic() if snapshot["total_packets"] else None
        self.last_packet_ts = snapshot["now"] if snapshot["total_packets"] else None
        self.source_error = None

    def packet_received(self, ts):
        try:
            timestamp = float(ts)
            if not math.isfinite(timestamp):
                timestamp = None
        except (TypeError, ValueError, OverflowError):
            timestamp = None
        with self.lock:
            self.last_packet_monotonic = time.monotonic()
            self.source_error = None
            if timestamp is not None:
                self.last_packet_ts = timestamp

    def record_error(self, error):
        with self.lock:
            self.source_error = str(error)

    def status(self):
        with self.lock:
            last_seen = self.last_packet_monotonic
            age = max(0.0, time.monotonic() -
                      (self.started_at if last_seen is None else last_seen))
            stale = age >= self.stale_after_s or self.source_error is not None
            source_status = "error" if self.source_error is not None else ("stale" if stale else "healthy")
            return {
                "source_status": source_status,
                "source_stale": stale,
                "source_age_s": round(age, 3),
                "source_last_packet_ts": self.last_packet_ts,
                "source_error": self.source_error,
            }


class SnapshotCache:
    """Keep engine snapshots at one hertz regardless of the number of HTTP clients."""

    def __init__(self, engine):
        self.engine = engine
        self.lock = threading.Lock()
        self.refreshed_at = 0.0
        self.snapshot = None
        self.samples = []

    def get(self):
        now = time.monotonic()
        with self.lock:
            if self.snapshot is None or now - self.refreshed_at >= 1.0:
                self.snapshot = self.engine.snapshot()
                self.refreshed_at = now
                self.samples.append((now, self.snapshot["total_packets"]))
                cutoff = now - 10.0
                while len(self.samples) > 2 and self.samples[1][0] <= cutoff:
                    self.samples.pop(0)
            return self.snapshot

    def packets_per_s(self):
        self.get()
        with self.lock:
            if len(self.samples) < 2:
                return 0.0
            end_time, end_count = self.samples[-1]
            cutoff = end_time - 10.0
            start_count = self.samples[0][1]
            start_time = max(cutoff, self.samples[0][0])
            for left, right in zip(self.samples, self.samples[1:]):
                if left[0] <= cutoff < right[0]:
                    span = right[0] - left[0]
                    fraction = (cutoff - left[0]) / span if span else 0
                    start_count = left[1] + fraction * (right[1] - left[1])
                    start_time = cutoff
                    break
                if right[0] <= cutoff:
                    start_count, start_time = right[1], right[0]
            elapsed = max(0.001, end_time - start_time)
            return max(0.0, (end_count - start_count) / elapsed)


def _persist_bins(engine, store, last_t):
    bins = engine.bins
    if not bins or bins[-1]["t"] <= last_t:
        return last_t
    for row in list(bins):
        if row["t"] > last_t:
            store.add_minute_stat(row)
            last_t = row["t"]
    return last_t


def _consume(engine, source, store, source_name, stop_event, source_health=None):
    first_ts = last_ts = None
    try:
        for packet in source():
            if stop_event.is_set():
                break
            ts, data, *linktype_value = packet
            linktype = linktype_value[0] if linktype_value else 1
            first_ts = ts if first_ts is None else first_ts
            last_ts = ts
            if source_health is not None:
                source_health.packet_received(ts)
            engine.process(ts, data, linktype)
    except Exception as exc:
        if source_health is not None:
            source_health.record_error(exc)
        logging.exception("Packet source stopped with an error")
    finally:
        try:
            engine.finish()
            snapshot = engine.snapshot()
            store.record_capture(source_name, snapshot["total_packets"], snapshot["total_bytes"],
                                 snapshot["malformed"], first_ts, last_ts,
                                 store.counters()["dropped"])
            store.flush()
        except Exception:
            logging.exception("Could not finalize capture data")


def make_handler(engine, store, token, source, policy, results_dir, started_at, snapshots=None,
                 source_health=None):
    snapshots = snapshots or SnapshotCache(engine)
    source_health = source_health or SourceHealth(engine, started_at)
    results_path = Path(results_dir)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body, content_type, api=False):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if api:
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, value):
            body = json.dumps(value, ensure_ascii=False, allow_nan=False,
                              separators=(",", ":")).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8", api=True)

        def send_error(self, code, message=None, explain=None):
            self._json(code, {"error": message or "request rejected"})

        def _reject_method(self):
            if not self._host_allowed():
                self._json(403, {"error": "Host header is not allowed"})
            else:
                self._json(405, {"error": "method not allowed"})

        def _host_allowed(self):
            authority = self.headers.get("Host", "")
            try:
                parsed = urlsplit("//" + authority)
                port = parsed.port
            except ValueError:
                return False
            return (parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                    and parsed.username is None and parsed.password is None
                    and not parsed.path and not parsed.query and not parsed.fragment
                    and port == self.server.server_port)

        def _request_url(self):
            try:
                return urlsplit(self.path)
            except ValueError as exc:
                raise ValueError("invalid request URL") from exc

        @staticmethod
        def _query(query):
            values = parse_qs(query, keep_blank_values=True, max_num_fields=20)
            if any(len(items) != 1 for items in values.values()):
                raise ValueError("query parameters may appear only once")
            return {key: items[0] for key, items in values.items()}

        @staticmethod
        def _page(query):
            try:
                limit = int(query.get("limit", "50"))
                offset = int(query.get("offset", "0"))
            except ValueError as exc:
                raise ValueError("limit and offset must be integers") from exc
            if not 1 <= limit <= MAX_PAGE_SIZE:
                raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
            if not 0 <= offset <= MAX_OFFSET:
                raise ValueError(f"offset must be between 0 and {MAX_OFFSET}")
            return limit, offset

        def do_GET(self):
            if not self._host_allowed():
                self._json(403, {"error": "Host header is not allowed"})
                return
            try:
                url = self._request_url()
                path = url.path
                if path in STATIC_FILES:
                    name, content_type = STATIC_FILES[path]
                    body = (STATIC_DIR / name).read_bytes()
                    if name == "index.html":
                        html = body.decode("utf-8").replace(
                            '<meta name="packetlens-token" content="">',
                            f'<meta name="packetlens-token" content="{token}">')
                        body = html.encode("utf-8")
                    self._send(200, body, content_type)
                    return
                if path == "/api/health":
                    snapshot = snapshots.get()
                    source_state = source_health.status()
                    store_counters = store.counters()
                    degraded_reasons = []
                    if source_state.get("source_error") is not None:
                        degraded_reasons.append("source_error")
                    elif source_state["source_stale"]:
                        degraded_reasons.append("source_stale")
                    if store_counters["status"] == "error":
                        degraded_reasons.append("store_writer_error")
                    elif store_counters["status"] == "degraded":
                        degraded_reasons.append("store_drops")
                    if (store_counters["status"] == "error" or
                            source_state["source_status"] == "error"):
                        service_status = "unhealthy"
                    elif degraded_reasons:
                        service_status = "degraded"
                    else:
                        service_status = "healthy"
                    self._json(200, {
                        "uptime_s": max(0, time.monotonic() - started_at),
                        "service_status": service_status,
                        "degraded_reasons": degraded_reasons,
                        "source": source,
                        "packets_total": snapshot["total_packets"],
                        "bytes_total": snapshot["total_bytes"],
                        "malformed": snapshot["malformed"],
                        "packets_per_s": snapshots.packets_per_s(),
                        "avg_processing_us": snapshot.get("avg_processing_us", 0.0),
                        "max_processing_us": snapshot.get("max_processing_us", 0.0),
                        "memory_rss_bytes": _process_rss_bytes(),
                        "now": snapshot["now"],
                        **source_state,
                        "store_status": store_counters["status"],
                        "store_error": store_counters["writer_error"],
                        "store_counters": store_counters,
                        "policy": policy.name,
                        "version": __version__,
                    })
                    return
                if path == "/api/overview":
                    query = self._query(url.query)
                    window = query.get("window", "300")
                    if window not in {"300", "900", "3600"}:
                        raise ValueError("window must be 300, 900, or 3600")
                    snapshot = snapshots.get()
                    packet_time = snapshot["now"]
                    start_time = max(0, packet_time - int(window))
                    bins_by_time = {row["t"]: row for row in store.minute_stats(start_time, packet_time)}
                    for row in snapshot["bins"]:
                        if start_time <= row["t"] <= packet_time:
                            bins_by_time[row["t"]] = row
                    bins = [bins_by_time[key] for key in sorted(bins_by_time)]
                    summary = store.summary()
                    recent = store.list_incidents(limit=10, offset=0)["items"]
                    open_by_severity = {
                        severity: int(summary["open_by_severity"].get(severity, 0))
                        for severity in ("critical", "high", "medium", "low")
                    }
                    self._json(200, {
                        "window": int(window),
                        "bins": bins,
                        "protocol_mix": snapshot["protocols"],
                        "top_talkers": snapshot["talkers"],
                        "open_incidents_by_severity": open_by_severity,
                        "recent_incidents": recent,
                    })
                    return
                if path == "/api/incidents":
                    query = self._query(url.query)
                    limit, offset = self._page(query)
                    status, severity = query.get("status"), query.get("severity")
                    if status and status not in STATUSES:
                        raise ValueError("invalid incident status filter")
                    if severity and severity not in SEVERITIES:
                        raise ValueError("invalid incident severity filter")
                    if len(query.get("kind", "")) > 100 or len(query.get("q", "")) > 200:
                        raise ValueError("kind or q exceeds the maximum length")
                    result = store.list_incidents(status=status or None, severity=severity or None,
                                                  kind=query.get("kind") or None, q=query.get("q") or None,
                                                  limit=limit, offset=offset)
                    self._json(200, result)
                    return
                if path.startswith("/api/incidents/"):
                    parts = path.split("/")
                    if len(parts) == 4 and parts[3]:
                        incident = store.get_incident(unquote(parts[3]))
                        if incident is None:
                            self._json(404, {"error": "incident not found"})
                        else:
                            self._json(200, incident)
                        return
                if path == "/api/hosts":
                    query = self._query(url.query)
                    limit, offset = self._page(query)
                    sort = query.get("sort", "bytes")
                    if sort not in {"bytes", "last_seen", "alerts", "ip"}:
                        raise ValueError("sort must be bytes, last_seen, alerts, or ip")
                    if len(query.get("q", "")) > 200:
                        raise ValueError("q exceeds the maximum length")
                    self._json(200, store.list_hosts(q=query.get("q") or None, sort=sort,
                                                     limit=limit, offset=offset))
                    return
                if path.startswith("/api/hosts/"):
                    parts = path.split("/")
                    if len(parts) == 4 and parts[3]:
                        host = store.get_host(unquote(parts[3]))
                        if host is None:
                            self._json(404, {"error": "host not found"})
                        else:
                            self._json(200, host)
                        return
                if path == "/api/policies":
                    self._json(200, policy.to_dict())
                    return
                if path == "/api/quality":
                    items = []
                    if results_path.exists():
                        if not results_path.is_dir():
                            raise OSError("results path is not a directory")
                        for item in sorted(results_path.glob("*.json")):
                            if item.is_file():
                                modified = datetime.fromtimestamp(
                                    item.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")
                                items.append({"name": item.name, "modified": modified})
                    self._json(200, {"items": items})
                    return
                if path.startswith("/api/quality/"):
                    name = path[len("/api/quality/"):]
                    if (not name or not name.endswith(".json") or
                            any(separator in name for separator in ("/", "\\")) or "%" in name):
                        self._json(404, {"error": "result file not found"})
                        return
                    if not results_path.exists():
                        self._json(404, {"error": "result file not found"})
                        return
                    if not results_path.is_dir():
                        raise OSError("results path is not a directory")
                    listed_names = {
                        item.name for item in results_path.glob("*.json") if item.is_file()
                    }
                    if name not in listed_names:
                        self._json(404, {"error": "result file not found"})
                        return
                    result_path = results_path / name
                    if result_path.stat().st_size > MAX_BODY:
                        self._json(400, {"error": "result file is too large"})
                        return
                    with result_path.open("rb") as result_file:
                        raw = result_file.read(MAX_BODY + 1)
                    if len(raw) > MAX_BODY:
                        self._json(400, {"error": "result file is too large"})
                        return
                    try:
                        def reject_constant(value):
                            raise ValueError(f"invalid JSON constant {value}")
                        report = json.loads(raw.decode("utf-8"), parse_constant=reject_constant)
                    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                        self._json(400, {"error": f"result file is not valid JSON: {exc}"})
                        return
                    self._json(200, report)
                    return
                self._json(404, {"error": "not found"})
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except (OSError, RuntimeError) as exc:
                logging.exception("Dashboard GET failed")
                self._json(500, {"error": str(exc)})
            except Exception:
                logging.exception("Dashboard GET failed unexpectedly")
                self._json(500, {"error": "internal server error"})

        def do_POST(self):
            if not self._host_allowed():
                self._json(403, {"error": "Host header is not allowed"})
                return
            supplied = self.headers.get("X-PacketLens-Token", "")
            try:
                token_matches = hmac.compare_digest(token, supplied)
            except TypeError:
                token_matches = False
            if not token_matches:
                self._json(403, {"error": "invalid or missing dashboard token"})
                return
            try:
                url = self._request_url()
                parts = url.path.split("/")
                if len(parts) != 5 or parts[1:3] != ["api", "incidents"] or parts[4] != "status":
                    self._json(404, {"error": "not found"})
                    return
                if not parts[3]:
                    self._json(404, {"error": "incident not found"})
                    return
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length or "")
                except ValueError as exc:
                    raise ValueError("Content-Length is required") from exc
                if length < 0 or length > MAX_BODY:
                    self.close_connection = True
                    raise ValueError("request body is too large or invalid")
                if self.headers.get_content_type() != "application/json":
                    raise ValueError("Content-Type must be application/json")
                try:
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError("request body must be valid JSON") from exc
                if not isinstance(body, dict) or set(body) != {"status", "note"}:
                    raise ValueError("body must contain status and note")
                if not isinstance(body["status"], str) or body["status"] not in {"acknowledged", "closed"}:
                    raise ValueError("status must be acknowledged or closed")
                if not isinstance(body["note"], str) or len(body["note"]) > 4000:
                    raise ValueError("note must be a string of at most 4000 characters")
                incident_id = unquote(parts[3])
                if store.get_incident(incident_id) is None:
                    self._json(404, {"error": "incident not found"})
                    return
                updated = store.set_incident_status(incident_id, body["status"], body["note"])
                self._json(200, updated)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except (OSError, RuntimeError) as exc:
                logging.exception("Dashboard POST failed")
                self._json(500, {"error": str(exc)})
            except Exception:
                logging.exception("Dashboard POST failed unexpectedly")
                self._json(500, {"error": "internal server error"})

        def do_HEAD(self):
            self._reject_method()

        def do_PUT(self):
            self._reject_method()

        def do_PATCH(self):
            self._reject_method()

        def do_DELETE(self):
            self._reject_method()

        def do_OPTIONS(self):
            self._reject_method()

        def log_message(self, fmt, *args):
            logging.info("dashboard %s - %s", self.address_string(), fmt % args)

    return Handler


def serve(engine, source, host="127.0.0.1", port=8080, *, store=None, source_name="live",
          policy=None, results_dir="results"):
    """Serve the console while a packet-source callable yields (timestamp, bytes[, linktype])."""
    token = secrets.token_urlsafe(32)
    store = store or getattr(engine, "store", None)
    if store is None:
        store = Store("packetlens.db")
    policy = policy or effective_policy()
    store.incident_gap_s = policy.incident_gap_s
    started_at = time.monotonic()
    stop_event = threading.Event()
    snapshots = SnapshotCache(engine)
    source_health = SourceHealth(engine, started_at)
    server = ThreadingHTTPServer(
        (host, port), make_handler(engine, store, token, source_name, policy, results_dir,
                                   started_at, snapshots, source_health))
    server.daemon_threads = True
    worker = threading.Thread(target=_consume,
                              args=(engine, source, store, source_name, stop_event, source_health),
                              name="packetlens-packet-source", daemon=True)
    refresher = threading.Thread(target=_refresh_snapshots, args=(snapshots, stop_event),
                                 name="packetlens-dashboard-snapshot", daemon=True)
    worker.start()
    refresher.start()
    actual_port = server.server_address[1]
    print(f"Dashboard on http://{host}:{actual_port}  token={token}  (Ctrl-C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()
        worker.join(timeout=1.0)
        store.flush()
        if not worker.is_alive():
            store.close()


def _refresh_snapshots(snapshots, stop_event):
    while not stop_event.is_set():
        snapshots.get()
        stop_event.wait(0.25)


def replay_packets(packets, speed=1.0, loop=False):
    """Return a packet source that preserves capture timing while replaying."""
    if speed <= 0:
        raise ValueError("replay speed must be greater than zero")

    def run():
        while True:
            first, start = None, time.monotonic()
            for packet in packets():
                ts, data, *extra = packet
                first = ts if first is None else first
                delay = (ts - first) / speed - (time.monotonic() - start)
                if delay > 0.002:
                    time.sleep(min(delay, 1.0))
                yield (ts, data, *extra)
            if not loop:
                return
    return run


def replay(engine, packets, linktype, speed=1.0, loop=False):
    """Backward-compatible helper for callers that directly replay into an engine."""
    def run():
        for packet in replay_packets(packets, speed, loop)():
            ts, data, *rest = packet
            engine.process(ts, data, rest[0] if rest else linktype)
    return run
