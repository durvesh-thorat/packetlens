import json
import subprocess
import sys
import unittest
from pathlib import Path

from packetlens.evaluate import evaluate_rules
from packetlens.policy import Policy, default_policy_path, load_policy, validate_policy

ROOT = Path(__file__).resolve().parents[1]


class DetectionValidationTests(unittest.TestCase):
    def test_experimental_policy_flag_validation_and_default_policy(self):
        default = load_policy(default_policy_path())
        experimental_by_det = {
            r["detector"]: bool(r.get("experimental", False)) for r in default.policies
        }
        self.assertEqual(
            experimental_by_det,
            {
                "port_scan": False,
                "syn_flood": False,
                "dns_tunnel": False,
                "arp_spoof": False,
                "horizontal_scan": False,
                "volumetric": True,
            },
        )

        raw = json.loads(default_policy_path().read_text(encoding="utf-8"))
        self.assertEqual(validate_policy(raw), [])

        bad = json.loads(json.dumps(raw))
        bad["policies"][0]["experimental"] = "yes"
        errors = validate_policy(bad)
        self.assertTrue(
            any(err.startswith("$.policies[0].experimental:") for err in errors),
            errors,
        )
        with self.assertRaises(ValueError):
            Policy(bad)

    def test_held_out_per_rule_evaluation_and_bootstrap_ci(self):
        # 3 x 600s = 30 clean 1-minute bins, enough for Circular Block Bootstrap CI
        report = evaluate_rules(
            benign_duration=600,
            attack_duration=300,
            benign_seeds=(101, 102, 103),
            attack_seeds=(201,),
        )
        self.assertEqual(report["clean_hours"], 0.5)
        by_det = {row["detector"]: row for row in report["rules"]}
        for sig_det in ("port_scan", "syn_flood", "dns_tunnel", "arp_spoof", "horizontal_scan"):
            row = by_det[sig_det]
            self.assertEqual(row["fn"], 0, row)
            self.assertEqual(row["fp_outside_window"], 0, row)
            self.assertEqual(row["recall"], 1.0, row)
            self.assertEqual(row["precision"], 1.0, row)
            self.assertEqual(row["clean_fp_per_hour"], 0.0, row)
            self.assertEqual(row["clean_fp_per_hour_ci95"], [0.0, 0.0], row)
            self.assertTrue(row["meets_m0_synthetic_target"], row)
            self.assertFalse(row["experimental"], row)

        vol = by_det["volumetric"]
        self.assertTrue(vol["experimental"])
        self.assertGreater(vol["clean_fp_per_hour"], 1.0)
        self.assertIsNotNone(vol["clean_fp_per_hour_ci95"])
        self.assertFalse(vol["meets_m0_synthetic_target"])

    def test_evaluate_rules_cli_outputs_valid_json(self):
        res = subprocess.run(
            [sys.executable, "-m", "packetlens", "evaluate", "--rules", "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["clean_hours"], 1.0)
        self.assertEqual(len(data["rules"]), 6)


if __name__ == "__main__":
    unittest.main()
