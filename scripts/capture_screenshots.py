import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packetlens.dashboard import SnapshotCache, SourceHealth, make_handler
from packetlens.engine import Engine
from packetlens.policy import effective_policy
from packetlens.store import Store
from packetlens.synth import generate

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


class _CdpClient:
    """Minimal stdlib RFC 6455 WebSocket client for headless Edge CDP."""

    def __init__(self, ws_url):
        parsed = urlsplit(ws_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 80
        path = parsed.path or "/"
        self._sock = socket.create_connection((host, port), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(req.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise RuntimeError("WebSocket handshake closed")
            buf += chunk
        header_end = buf.index(b"\r\n\r\n") + 4
        head = buf[:header_end].decode("latin1")
        if "101 " not in head.splitlines()[0]:
            raise RuntimeError(f"WebSocket upgrade failed: {head.splitlines()[0]}")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if expected not in head:
            raise RuntimeError("Invalid Sec-WebSocket-Accept")
        self._extra = buf[header_end:]
        self._msg_id = 0

    def _read_exact(self, n):
        out = bytearray()
        if self._extra:
            take = min(n, len(self._extra))
            out.extend(self._extra[:take])
            self._extra = self._extra[take:]
        while len(out) < n:
            chunk = self._sock.recv(n - len(out))
            if not chunk:
                raise EOFError("WebSocket closed")
            out.extend(chunk)
        return bytes(out)

    def _send_frame(self, text):
        payload = text.encode("utf-8")
        mask = os.urandom(4)
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", n))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(bytes(header) + masked)

    def _recv_message(self):
        chunks = []
        while True:
            b1, b2 = self._read_exact(2)
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if b2 & 0x80:
                mask = self._read_exact(4)
                raw = self._read_exact(length)
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(raw))
            else:
                data = self._read_exact(length)
            if opcode == 0x8:
                raise EOFError("WebSocket close frame")
            if opcode == 0x9:
                continue
            chunks.append(data)
            if fin:
                return b"".join(chunks).decode("utf-8")

    def call(self, method, params=None):
        self._msg_id += 1
        cid = self._msg_id
        self._send_frame(json.dumps({"id": cid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self._recv_message())
            if msg.get("id") == cid:
                if "error" in msg:
                    raise RuntimeError(f"CDP {method} failed: {msg['error']}")
                return msg.get("result", {})

    def close(self):
        self._sock.close()


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _seed_demo_store(store, policy):
    frames, _events = generate(300, seed=8, attacks=True)
    engine = Engine(policy=policy, store=store)
    snapshots = SnapshotCache(engine)
    split = int(len(frames) * 0.85)
    for ts, data in frames[:split]:
        engine.process(ts, data)
    snapshots.get()
    time.sleep(1.05)
    for ts, data in frames[split:]:
        engine.process(ts, data)
    engine.finish()
    first_ts = frames[0][0] if frames else None
    last_ts = frames[-1][0] if frames else None
    snap = engine.snapshot()
    store.record_capture(
        "synth:demo-300s",
        snap["total_packets"],
        snap["total_bytes"],
        snap["malformed"],
        first_ts,
        last_ts,
        store.counters()["dropped"],
    )
    store.flush()
    snapshots.get()
    return engine, snapshots, "synth:demo-300s", (last_ts or 1700000000.0)


def _capture_cdp(cdp, url, out_file, width, height, mobile=False, click_text=None):
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cdp.call("Emulation.setDeviceMetricsOverride", {
        "width": width,
        "height": height,
        "deviceScaleFactor": 1,
        "mobile": mobile,
    })
    cdp.call("Page.navigate", {"url": url})
    for _ in range(40):
        res = cdp.call("Runtime.evaluate", {
            "expression": (
                "(() => {"
                "const title = document.querySelector('#view .page-title');"
                "const loading = Array.from(document.querySelectorAll('#view .state-message')).some(e => /Loading/i.test(e.textContent));"
                "return Boolean(title) && !loading;"
                "})()"
            ),
            "returnByValue": True,
        })
        if res.get("result", {}).get("value") is True:
            break
        time.sleep(0.1)
    if click_text:
        cdp.call("Runtime.evaluate", {
            "expression": (
                f"(() => {{ const b = Array.from(document.querySelectorAll('button')).find(x => x.textContent.trim() === {json.dumps(click_text)}); if (b) b.click(); }})()"
            )
        })
        time.sleep(0.35)
    time.sleep(0.25)
    dims = cdp.call("Runtime.evaluate", {
        "expression": "[document.documentElement.clientWidth, document.documentElement.scrollWidth]",
        "returnByValue": True,
    }).get("result", {}).get("value", [width, width])
    shot = cdp.call("Page.captureScreenshot", {"format": "png"})
    out_file.write_bytes(base64.b64decode(shot["data"]))
    overflow = dims[1] > dims[0]
    status = f"OVERFLOW {dims[1]}>{dims[0]}" if overflow else f"fit {dims[0]}px"
    print(f"Captured {out_file} ({out_file.stat().st_size:,} bytes, {status})")
    if overflow:
        raise RuntimeError(f"Horizontal overflow on {out_file.name}: scrollWidth={dims[1]} > clientWidth={dims[0]}")


def main():
    parser = argparse.ArgumentParser(description="Capture PacketLens dashboard screenshots via headless Edge CDP.")
    parser.add_argument("--db", help="Optional existing SQLite DB path; generates synthetic demo DB when omitted.")
    parser.add_argument("--out-dir", default="assets", help="Directory for README screenshots (default: assets).")
    parser.add_argument("--verify-dir", help="Optional directory for full desktop/light/mobile verification matrix.")
    parser.add_argument("--edge", default=EDGE_PATH, help="Path to Microsoft Edge executable.")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    policy = effective_policy()
    temp_dir = None

    if args.db:
        store = Store(args.db)
        bounds = store.time_bounds()
        last_t = bounds["last_t"] or 1700000000.0
        engine = Engine(policy=policy, store=store)
        snapshots = SnapshotCache(engine)
        source_name = f"db:{Path(args.db).name}"
    else:
        temp_dir = tempfile.TemporaryDirectory()
        store = Store(Path(temp_dir.name) / "demo.db")
        engine, snapshots, source_name, last_t = _seed_demo_store(store, policy)

    source_health = SourceHealth(engine, time.monotonic(), stale_after_s=3600.0)
    source_health.packet_received(last_t)
    results_dir = ROOT / "results"
    handler = make_handler(
        engine,
        store,
        "screen-token",
        source_name,
        policy,
        results_dir,
        time.monotonic(),
        snapshots=snapshots,
        source_health=source_health,
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    print(f"Server listening on http://127.0.0.1:{port}")

    edge_port = _free_port()
    edge_profile = tempfile.TemporaryDirectory()
    edge_proc = subprocess.Popen(
        [
            args.edge,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            f"--user-data-dir={edge_profile.name}",
            f"--remote-debugging-port={edge_port}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    cdp = None
    try:
        ws_url = None
        for _ in range(40):
            try:
                targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{edge_port}/json", timeout=1).read())
                page_target = next((t for t in targets if t.get("type") == "page"), targets[0] if targets else None)
                if page_target and "webSocketDebuggerUrl" in page_target:
                    ws_url = page_target["webSocketDebuggerUrl"]
                    break
            except Exception:
                time.sleep(0.15)
        if not ws_url:
            raise RuntimeError("Could not connect to Edge CDP target")

        cdp = _CdpClient(ws_url)
        cdp.call("Page.enable")
        cdp.call("Runtime.enable")

        incidents = store.list_incidents(limit=50)["items"]
        vol_inc = next((i for i in incidents if i["kind"] == "volumetric"), None)
        first_inc_id = (vol_inc or incidents[0])["id"] if incidents else ""
        syn_inc = next((i for i in incidents if i["kind"] in ("port_scan", "syn_flood", "dns_tunnel")), None)
        syn_inc_id = syn_inc["id"] if syn_inc else first_inc_id

        hosts = store.list_hosts(sort="bytes", limit=10)["items"]
        rich_host = next((h for h in hosts if h.get("alert_count", 0) > 0 and h.get("top_ports")), None)
        first_host_ip = (rich_host or hosts[0])["ip"] if hosts else ""

        # Primary 3 README screenshots (1440x900 dark)
        readme_shots = [
            ("overview.png", "#/overview"),
            ("incidents.png", f"#/incidents/{first_inc_id}" if first_inc_id else "#/incidents"),
            ("hosts.png", f"#/hosts/{first_host_ip}" if first_host_ip else "#/hosts"),
        ]
        for fname, route in readme_shots:
            _capture_cdp(cdp, f"http://127.0.0.1:{port}/{route}", out_dir / fname, 1440, 900)

        # Full verification matrix across all 5 views, light mode, and 390x844 mobile
        if args.verify_dir:
            vdir = Path(args.verify_dir)
            desktop_pages = [
                ("desktop_dark_overview.png", "#/overview", None),
                ("desktop_dark_incidents.png", "#/incidents", None),
                ("desktop_dark_incident_volumetric.png", f"#/incidents/{first_inc_id}", None),
                ("desktop_dark_incident_rule.png", f"#/incidents/{syn_inc_id}", None),
                ("desktop_dark_hosts.png", f"#/hosts/{first_host_ip}", None),
                ("desktop_dark_quality_eval.png", "#/quality", "Synthetic Rule Evaluation"),
                ("desktop_dark_quality_ml.png", "#/quality", "Bot Classifier & Leakage"),
                ("desktop_dark_quality_hf.png", "#/quality", "Curated PCAPs (HF)"),
                ("desktop_dark_policies.png", "#/policies", None),
                ("desktop_light_overview.png", "/?theme=light#/overview", None),
                ("desktop_light_incident.png", f"/?theme=light#/incidents/{first_inc_id}", None),
                ("desktop_light_quality.png", "/?theme=light#/quality", "Synthetic Rule Evaluation"),
            ]
            for fname, route, click_tab in desktop_pages:
                path = route if route.startswith("/") else f"/{route}"
                _capture_cdp(cdp, f"http://127.0.0.1:{port}{path}", vdir / fname, 1440, 900, click_text=click_tab)

            mobile_pages = [
                ("mobile_dark_overview.png", "/?theme=dark#/overview"),
                ("mobile_dark_incidents.png", f"/?theme=dark#/incidents/{first_inc_id}"),
                ("mobile_dark_hosts.png", f"/?theme=dark#/hosts/{first_host_ip}"),
                ("mobile_dark_quality.png", "/?theme=dark#/quality"),
                ("mobile_dark_policies.png", "/?theme=dark#/policies"),
            ]
            for fname, route in mobile_pages:
                _capture_cdp(cdp, f"http://127.0.0.1:{port}{route}", vdir / fname, 390, 844, mobile=True)
    finally:
        if cdp is not None:
            cdp.close()
        edge_proc.terminate()
        edge_proc.wait(timeout=5)
        edge_profile.cleanup()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        store.close()
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    main()
