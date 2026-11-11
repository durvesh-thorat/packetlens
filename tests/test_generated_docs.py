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


if __name__ == "__main__":
    unittest.main()
