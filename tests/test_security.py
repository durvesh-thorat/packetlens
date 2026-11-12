import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from packetlens.dashboard import CSP, SourceHealth, is_loopback_host, make_handler, serve
from packetlens.detectors import Alert
from packetlens.engine import Engine
from packetlens.pcap import PcapError, PcapReader
from packetlens.policy import Policy, effective_policy
from packetlens.report import render_report
from packetlens.store import Store


ROOT = Path(__file__).resolve().parents[1]


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "security.db")
        self.store = Store(self.db_path)
        self.engine = Engine(store=self.store)
        self.incident_id = self.store.add_alert(Alert(
            1_700_000_001.0,
            "dns_tunnel",
            "high",
            "<script>alert('src')</script>",
            "Query \" onclick=\"alert(2)\" <img src=x onerror=alert(3)>",
            "10.0.0.2",
            policy_id="<svg onload=alert(4)>",
            data={"observed": "<script>1</script>", "threshold": 10},
        ))
        self.store.flush()
        self.results = Path(self.temp.name) / "results"
        self.results.mkdir()
        self.token = "secret-sec-token"
        handler = make_handler(
            self.engine, self.store, self.token, "sec.pcap",
            effective_policy(), self.results, 0.0,
            source_health=SourceHealth(self.engine, 0.0),
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.temp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_security_headers_and_index_no_store(self):
        self.assertIn("frame-ancestors 'none'", CSP)
        self.assertIn("base-uri 'none'", CSP)
        self.assertIn("form-action 'self'", CSP)
        for path in ("/", "/index.html"):
            status, headers, body = self._request("GET", path)
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Security-Policy"], CSP)
            self.assertEqual(headers["X-Frame-Options"], "DENY")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn(self.token.encode(), body)

    def test_post_origin_token_and_body_validation(self):
        path = f"/api/incidents/{self.incident_id}/status"
        valid_body = json.dumps({"status": "acknowledged", "note": "ok"})

        # Non-loopback Origin rejected even with valid token
        status, _, _ = self._request(
            "POST", path, valid_body,
            {
                "Content-Type": "application/json",
                "X-PacketLens-Token": self.token,
                "Origin": "https://evil.example",
            },
        )
        self.assertEqual(status, 403)

        # Loopback Origin with wrong port rejected
        status, _, _ = self._request(
            "POST", path, valid_body,
            {
                "Content-Type": "application/json",
                "X-PacketLens-Token": self.token,
                "Origin": f"http://127.0.0.1:{self.port + 1}",
            },
        )
        self.assertEqual(status, 403)

        # Wrong token rejected
        status, _, _ = self._request(
            "POST", path, valid_body,
            {"Content-Type": "application/json", "X-PacketLens-Token": "wrong-token"},
        )
        self.assertEqual(status, 403)

        # Wrong Content-Type rejected
        status, _, _ = self._request(
            "POST", path, valid_body,
            {"Content-Type": "text/plain", "X-PacketLens-Token": self.token},
        )
        self.assertEqual(status, 400)

        # Oversized Content-Length rejected cleanly before reading body
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            conn.putrequest("POST", path)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("X-PacketLens-Token", self.token)
            conn.putheader("Content-Length", str(1024 * 1024 + 10))
            conn.endheaders()
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 400)
        finally:
            conn.close()

        # Oversized note (> 4000 chars) rejected
        status, _, _ = self._request(
            "POST", path,
            json.dumps({"status": "acknowledged", "note": "a" * 4001}),
            {"Content-Type": "application/json", "X-PacketLens-Token": self.token},
        )
        self.assertEqual(status, 400)

        # Extra JSON property rejected
        status, _, _ = self._request(
            "POST", path,
            json.dumps({"status": "acknowledged", "note": "ok", "extra": 1}),
            {"Content-Type": "application/json", "X-PacketLens-Token": self.token},
        )
        self.assertEqual(status, 400)

        # Valid loopback Origin and token succeeds
        status, _, body = self._request(
            "POST", path, valid_body,
            {
                "Content-Type": "application/json",
                "X-PacketLens-Token": self.token,
                "Origin": f"http://127.0.0.1:{self.port}",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "acknowledged")

    def test_unsupported_methods_and_host_rejected(self):
        for method in ("HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
            status, _, _ = self._request(method, "/api/health")
            self.assertEqual(status, 405, method)
            status, _, _ = self._request(
                method, "/api/health", headers={"Host": f"evil.example:{self.port}"}
            )
            self.assertEqual(status, 403, method)

    def test_quality_rejects_symlinks(self):
        target = self.results / "evaluation.json"
        target.write_text('{"ok": true}', encoding="utf-8")
        with patch.object(Path, "is_symlink", return_value=True):
            status, _, body = self._request("GET", "/api/quality/evaluation.json")
            self.assertEqual(status, 404)
            self.assertEqual(json.loads(body), {"error": "result file not found"})

    def test_sql_injection_payloads_do_not_bypass_queries(self):
        payloads = [
            "' OR '1'='1",
            "\"; DROP TABLE incidents; --",
            "%_\\",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9 --",
        ]
        for q in payloads:
            self.assertEqual(self.store.list_incidents(q=q)["total"], 0)
            self.assertEqual(self.store.list_hosts(q=q)["total"], 0)
            status, _, body = self._request(
                "GET", f"/api/incidents?q={quote(q, safe='')}"
            )
            # Some raw characters in URL path/query may return 400 or 200 with 0 results, never 500
            self.assertIn(status, (200, 400))
            if status == 200:
                self.assertEqual(json.loads(body)["total"], 0)

        # Incident table still intact after SQLi attempts
        self.assertEqual(self.store.list_incidents()["total"], 1)

    def test_report_escapes_xss_and_embeds_strict_csp(self):
        xss_policy = Policy({
            "version": 1,
            "name": "<script>alert('policy')</script>",
            "incident_gap_s": 300,
            "policies": [{
                "id": "rule-<script>",
                "detector": "dns_tunnel",
                "enabled": True,
                "action": "alert",
                "params": {},
                "allowlist": {"src": [], "dst": []},
            }],
        })
        doc = render_report(self.store, title="Report <script>alert(0)</script>", policy=xss_policy)
        self.assertIn("http-equiv=\"Content-Security-Policy\"", doc)
        self.assertIn("script-src 'none'", doc)
        for raw in (
            "<script>alert('src')</script>",
            "<img src=x onerror=alert(3)>",
            "<svg onload=alert(4)>",
            "<script>1</script>",
            "<script>alert('policy')</script>",
            "<script>alert(0)</script>",
            "\" onclick=\"alert(2)\"",
        ):
            self.assertNotIn(raw, doc)
        self.assertIn("&lt;script&gt;alert(&#x27;src&#x27;)&lt;/script&gt;", doc)

    def test_non_loopback_bind_refused_by_default(self):
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.10"))

        with self.assertRaisesRegex(ValueError, "refusing to bind dashboard without TLS"):
            serve(self.engine, lambda: iter(()), host="0.0.0.0", port=0, store=self.store)

        pcap = Path(self.temp.name) / "empty.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")
        res = subprocess.run(
            [sys.executable, "-m", "packetlens", "serve", "--pcap", str(pcap), "--host", "0.0.0.0", "--db", self.db_path],
            cwd=ROOT, capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("refusing to bind dashboard without TLS", res.stderr)

    def test_adversarial_malformed_pcap_rejected_safely(self):
        bad = Path(self.temp.name) / "bad.pcap"
        bad.write_bytes(b"NOT_A_PCAP_FILE_AT_ALL_0000")
        with self.assertRaises(PcapError):
            PcapReader(bad)


if __name__ == "__main__":
    unittest.main()
