"""Tiny HTTP server: serves one HTML page and a JSON snapshot that the page polls every second.

Polling (instead of WebSocket) keeps the server standard-library only and is plenty for a
1 Hz dashboard. Bound to 127.0.0.1 by default because the page exposes captured network data.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

INDEX = Path(__file__).parent / "static" / "index.html"


def make_handler(engine):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body, ctype = INDEX.read_bytes(), "text/html; charset=utf-8"
            elif self.path == "/api/snapshot":
                body, ctype = json.dumps(engine.snapshot()).encode(), "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    return Handler


def serve(engine, source, host="127.0.0.1", port=8080):
    """`source` is a generator-like callable that feeds `engine`; it runs in a background thread."""
    threading.Thread(target=source, daemon=True).start()
    server = ThreadingHTTPServer((host, port), make_handler(engine))
    print(f"Dashboard on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def replay(engine, packets, linktype, speed=1.0, loop=False):
    """Feed packets at (recorded time / speed) so a saved capture behaves like live traffic."""
    def run():
        while True:
            first, start = None, time.monotonic()
            for ts, data in packets():
                first = ts if first is None else first
                delay = (ts - first) / speed - (time.monotonic() - start)
                if delay > 0.002:
                    time.sleep(min(delay, 1.0))
                engine.process(ts, data, linktype)
            if not loop:
                return
    return run
