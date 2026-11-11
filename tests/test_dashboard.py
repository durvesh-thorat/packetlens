import http.client
import json
import re
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer

from packetlens import synth
from packetlens.dashboard import CSP, make_handler
from packetlens.detectors import Alert
from packetlens.engine import Engine
from packetlens.parsers import parse_packet
from packetlens.policy import effective_policy
from packetlens.report import write_report
from packetlens.store import Store


ROOT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp.name) / "dashboard.db")
        self.store = Store(self.db_path)
        self.engine = Engine(store=self.store)
        packet = parse_packet(1_700_000_000.25,
                              synth.tcp_frame("10.0.0.1", "10.0.0.2", 50000, 443, synth.ACK))
        self.engine.feed(packet)
        self.engine.finish()
        self.src = "<img src=x onerror=alert(1)>"
        self.detail = "Observed <img src=x onerror=alert(1)> from source"
        self.incident_id = self.store.add_alert(Alert(
            1_700_000_001.0, "test-rule", "high", self.src, self.detail, "10.0.0.2",
            data={"observed": 12, "threshold": 10}
        ))
        self.store.flush()
        self.token = "test-token"
        self.results = Path(self.temp.name) / "results"
        handler = make_handler(self.engine, self.store, self.token, "test capture",
                               effective_policy(), self.results, 0)
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

    def request(self, method, path, body=None, headers=None, raw_path=False):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        if raw_path:
            connection.putrequest(method, path, skip_accept_encoding=True)
            for name, value in (headers or {}).items():
                connection.putheader(name, value)
            connection.endheaders()
        else:
            connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        content = response.read()
        result = (response.status, dict(response.getheaders()), content)
        connection.close()
        return result

    def json_request(self, path):
        status, headers, body = self.request("GET", path)
        return status, headers, json.loads(body)

    def test_api_shapes_status_workflow_and_security_headers(self):
        status, headers, health = self.json_request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Security-Policy"], CSP)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertTrue({"uptime_s", "source", "packets_total", "bytes_total", "malformed",
                         "packets_per_s", "now", "store_counters", "policy", "version"} <= health.keys())
        self.assertEqual(health["source"], "test capture")

        status, _headers, overview = self.json_request("/api/overview?window=300")
        self.assertEqual(status, 200)
        self.assertTrue({"window", "bins", "protocol_mix", "top_talkers",
                         "open_incidents_by_severity", "recent_incidents"} <= overview.keys())
        for window in (900, 3600):
            self.assertEqual(self.json_request(f"/api/overview?window={window}")[0], 200)
        self.assertEqual(self.json_request("/api/overview?window=5")[0], 400)

        status, _headers, incidents = self.json_request("/api/incidents?limit=1&offset=0")
        self.assertEqual(status, 200)
        self.assertEqual(incidents["total"], 1)
        self.assertEqual(len(incidents["items"]), 1)
        self.assertEqual(incidents["items"][0]["src"], self.src)
        detail_status, _headers, incident = self.json_request(f"/api/incidents/{self.incident_id}")
        self.assertEqual(detail_status, 200)
        self.assertEqual(incident["alerts"][0]["src"], self.src)
        self.assertEqual(incident["alerts"][0]["detail"], self.detail)
        self.assertEqual(self.json_request("/api/incidents/missing")[0], 404)

        status, _headers, hosts = self.json_request("/api/hosts?sort=bytes&limit=10")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(hosts["total"], 2)
        host_status, _headers, host = self.json_request("/api/hosts/10.0.0.1")
        self.assertEqual(host_status, 200)
        self.assertEqual(host["ip"], "10.0.0.1")
        self.assertEqual(self.json_request("/api/hosts/192.0.2.99")[0], 404)

        status, _headers, policy = self.json_request("/api/policies")
        self.assertEqual(status, 200)
        self.assertIn("policies", policy)
        self.assertIn("name", policy)

        status, _headers, quality = self.json_request("/api/quality")
        self.assertEqual(status, 200)
        self.assertEqual(quality, {"items": []})
        self.results.mkdir()
        (self.results / "evaluation.json").write_text('{"untouched":true}', encoding="utf-8")
        status, _headers, quality = self.json_request("/api/quality")
        self.assertEqual(status, 200)
        self.assertEqual(quality["items"][0]["name"], "evaluation.json")
        self.assertIn("modified", quality["items"][0])
        status, _headers, report = self.json_request("/api/quality/evaluation.json")
        self.assertEqual(status, 200)
        self.assertEqual(report, {"untouched": True})

    def test_quality_result_name_validation_and_size_limit(self):
        self.results.mkdir()
        (self.results / "evaluation.json").write_text('{"ok":true}', encoding="utf-8")
        (self.results / "notes.txt").write_text("not JSON", encoding="utf-8")
        for path in ("/api/quality/../x", "/api/quality/%2e%2e%2f",
                     "/api/quality/not-listed.json", "/api/quality/notes.txt"):
            status, _headers, body = self.request("GET", path, raw_path=True)
            self.assertEqual(status, 404, path)
            self.assertEqual(set(json.loads(body)), {"error"})

        oversized = self.results / "oversized.json"
        oversized.write_bytes(b" " * (1024 * 1024 + 1))
        status, _headers, body = self.request("GET", "/api/quality/oversized.json")
        self.assertEqual(status, 400)
        self.assertEqual(set(json.loads(body)), {"error"})

        invalid = self.results / "invalid.json"
        invalid.write_text("{", encoding="utf-8")
        status, _headers, body = self.request("GET", "/api/quality/invalid.json")
        self.assertEqual(status, 400)
        self.assertEqual(set(json.loads(body)), {"error"})

        status, headers, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Security-Policy"], CSP)
        self.assertIn(self.token.encode(), page)
        self.assertEqual(self.request("GET", "/api/does-not-exist")[0], 404)

        payload = json.dumps({"status": "acknowledged", "note": "triaged"})
        status, _headers, _body = self.request(
            "POST", f"/api/incidents/{self.incident_id}/status", payload,
            {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 403)
        status, _headers, body = self.request(
            "POST", f"/api/incidents/{self.incident_id}/status", payload,
            {"Content-Type": "application/json", "X-PacketLens-Token": self.token}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "acknowledged")
        status, _headers, body = self.request(
            "POST", f"/api/incidents/{self.incident_id}/status",
            json.dumps({"status": "acknowledged", "note": "again"}),
            {"Content-Type": "application/json", "X-PacketLens-Token": self.token}
        )
        self.assertEqual(status, 400)
        self.assertEqual(set(json.loads(body)), {"error"})

    def test_host_header_and_traversal_rejected(self):
        wrong_host = {"Host": f"attacker.example:{self.port}"}
        status, _headers, body = self.request("GET", "/api/health", headers=wrong_host)
        self.assertEqual(status, 403)
        self.assertEqual(set(json.loads(body)), {"error"})
        for path in ("/../README.md", "/%2e%2e/README.md", "/%252e%252e/README.md"):
            status, _headers, body = self.request("GET", path, raw_path=True)
            self.assertEqual(status, 404, path)
            self.assertEqual(set(json.loads(body)), {"error"})

    def test_pagination_validation(self):
        for query in ("limit=501", "limit=0", "limit=abc", "offset=-1", "offset=10000001",
                      "limit=1&limit=2"):
            status, _headers, body = self.request("GET", f"/api/incidents?{query}")
            self.assertEqual(status, 400, query)
            self.assertEqual(set(json.loads(body)), {"error"})
        self.assertEqual(self.json_request("/api/hosts?sort=not-a-sort")[0], 400)

    def test_report_escapes_network_values_and_static_scripts_are_safe(self):
        out_path = Path(self.temp.name) / "report.html"
        write_report(self.db_path, out_path, '<img src=x onerror=alert(1)>')
        report = out_path.read_text(encoding="utf-8")
        escaped = "&lt;img src=x onerror=alert(1)&gt;"
        self.assertIn(escaped, report)
        self.assertNotIn(self.src, report)
        self.assertIn("Alert timeline", report)
        self.assertIn("Dropped store writes", report)
        self.assertIn("Policies in force", report)

        for script in (ROOT / "packetlens" / "static").glob("*.js"):
            source = script.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b|"
                                        r"document\.write|eval\s*\(", source, re.IGNORECASE), script)
        for asset in (ROOT / "packetlens" / "static").iterdir():
            if not asset.is_file():
                continue
            source = asset.read_text(encoding="utf-8")
            source = source.replace("http://www.w3.org/2000/svg", "")
            self.assertIsNone(re.search(r"https?://", source, re.IGNORECASE), asset)


if __name__ == "__main__":
    unittest.main()
