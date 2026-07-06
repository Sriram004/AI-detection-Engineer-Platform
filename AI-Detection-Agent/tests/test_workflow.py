import unittest
from pathlib import Path

from src.analyzer import analyze_alert, load_alert
from src.validator import final_status, validation_score


ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_powershell_analysis_generates_rules(self):
        alert = load_alert(ROOT / "data" / "alerts" / "powershell.json")
        analysis = analyze_alert(alert)

        self.assertEqual(analysis["mitre_mapping"]["technique_id"], "T1059.001")
        self.assertIn("EncodedCommand", analysis["sigma_rule"])
        self.assertIn("DeviceProcessEvents", analysis["kql_rule"])
        self.assertGreaterEqual(analysis["confidence"], 80)

    def test_all_sample_alerts_have_mitre_and_rules(self):
        for path in (ROOT / "data" / "alerts").glob("*.json"):
            with self.subTest(alert=path.name):
                analysis = analyze_alert(load_alert(path))
                self.assertTrue(analysis["mitre_mapping"]["technique_id"])
                self.assertTrue(analysis["sigma_rule"].startswith("title:"))
                self.assertIn("|", analysis["kql_rule"])

    def test_validation_requires_all_checks_for_approval(self):
        validation = {
            "mitre_ok": True,
            "logic_ok": True,
            "false_positives_ok": False,
            "response_ok": True,
            "status": "Approved",
        }

        self.assertEqual(validation_score(validation), 75)
        self.assertEqual(final_status(validation), "Needs Review")


if __name__ == "__main__":
    unittest.main()
