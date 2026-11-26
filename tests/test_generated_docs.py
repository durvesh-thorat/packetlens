import json
import re
import tempfile
import unittest
from pathlib import Path

from packetlens import __version__
from packetlens.policy import default_policy_path, load_policy
from packetlens.render_results import README_END, README_START, render_readme_section, render_results


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

    def test_readme_has_no_broken_local_docs_or_roadmap_links(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("](docs/", readme)
        self.assertNotIn("PRODUCTION_ROADMAP.md", readme)

    def test_package_version_matches_pyproject(self):
        self.assertEqual(__version__, "1.0.0")
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), __version__)

    def test_render_results_skips_missing_docs_dir_unless_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            readme = root / "README.md"
            readme.write_text(
                f"# Test\n\n{README_START}\nstale\n{README_END}\n",
                encoding="utf-8",
            )
            docs_results = root / "docs" / "RESULTS.md"

            written_docs, written_readme = render_results(
                results_dir=ROOT / "results",
                readme_path=readme,
                results_path=docs_results,
            )
            self.assertIsNone(written_docs)
            self.assertEqual(written_readme, readme)
            self.assertFalse(docs_results.parent.exists())
            updated = readme.read_text(encoding="utf-8")
            self.assertIn(render_readme_section().strip(), updated)

            written_docs, _ = render_results(
                results_dir=ROOT / "results",
                readme_path=readme,
                results_path=docs_results,
                write_docs=True,
            )
            self.assertEqual(written_docs, docs_results)
            self.assertTrue(docs_results.is_file())

            written_docs, _ = render_results(
                results_dir=ROOT / "results",
                readme_path=readme,
                results_path=docs_results,
            )
            self.assertEqual(written_docs, docs_results)


if __name__ == "__main__":
    unittest.main()
