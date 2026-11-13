import json
import unittest
from pathlib import Path

from packetlens.policy import default_policy_path, load_policy
from packetlens.render_results import README_END, README_START, render_readme_section


ROOT = Path(__file__).resolve().parents[1]


class GeneratedDocumentationTests(unittest.TestCase):
    def test_readme_results_marker_matches_freshly_rendered_output(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(readme.count(README_START), 1)
        self.assertEqual(readme.count(README_END), 1)
        section = readme.split(README_START, 1)[1].split(README_END, 1)[0].strip()
        self.assertEqual(section, render_readme_section().strip())

    def test_readme_policy_reference_resolves_to_valid_default_policy(self):
        policy_path = default_policy_path().resolve()
        self.assertEqual(policy_path, (ROOT / "packetlens" / "policies" / "default.json").resolve())
        self.assertIn("[`packetlens/policies/default.json`](packetlens/policies/default.json)",
                      (ROOT / "README.md").read_text(encoding="utf-8"))
        raw_policy = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertEqual(load_policy(policy_path).name, raw_policy["name"])
        self.assertTrue(raw_policy["policies"])

    def test_readme_has_exact_offline_flow_model_boundary(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "The flow-level machine learning experiments (Isolation Forest, Random Forest, "
            "Granite Time Series) run offline on CIC-IDS2017 flow tables. They are not part "
            "of the live packet pipeline.",
            readme,
        )

    def test_operations_runbook_exists_and_contains_core_sections(self):
        ops = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
        self.assertIn("## 1. Prerequisites and Installation", ops)
        self.assertIn("## 2. Standard Offline and Pilot Workflows", ops)
        self.assertIn("## 3. Observability and Health Monitoring", ops)
        self.assertIn("## 4. Incident Triage Standard Operating Procedure (SOP)", ops)
        self.assertIn("## 5. Backup, Retention, and Recovery", ops)
        self.assertIn("## 6. Safe Rollback Runbook", ops)
        self.assertIn("## 7. Graceful and Emergency Shutdown Runbook", ops)

    def test_pilot_protocol_exists_and_contains_safety_boundary(self):
        protocol = (ROOT / "docs" / "PILOT_PROTOCOL.md").read_text(encoding="utf-8")
        self.assertIn("## 1. Alert-Only Observation Protocol", protocol)
        self.assertIn("## 2. Section 6 Safety & Non-Fabrication Boundary", protocol)
        self.assertIn("## 3. Independent Source Comparison Methodology", protocol)
        self.assertIn("## 4. Operator Workload and Resource Usage Review", protocol)
        self.assertIn("## 5. Operational Checklists", protocol)

    def test_release_gate_exists_and_contains_criteria_and_risks(self):
        gate = (ROOT / "docs" / "RELEASE_GATE.md").read_text(encoding="utf-8")
        self.assertIn("## 1. Executive Summary & Target Scope Boundary", gate)
        self.assertIn("## 2. Release Gate Criteria Matrix", gate)
        self.assertIn("## 3. Operational & Security Review Findings", gate)
        self.assertIn("## 4. Residual Risk Register", gate)
        self.assertIn("## 5. Go / No-Go Decision Framework & Maintainer Sign-Off", gate)
        self.assertIn("RR-01", gate)
        self.assertIn("RR-08", gate)

    def test_pilot_results_exists_and_contains_metrics(self):
        results = (ROOT / "docs" / "PILOT_RESULTS.md").read_text(encoding="utf-8")
        self.assertIn("391,244", results)
        self.assertIn("64,097", results)
        self.assertIn("volumetric", results)
        self.assertIn("## 6. Known Limitations & Non-Generalization Boundaries", results)


if __name__ == "__main__":
    unittest.main()
