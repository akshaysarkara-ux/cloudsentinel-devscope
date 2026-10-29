import unittest

from src.risk_analyzer import (
    analyse_finding,
    prioritise_findings,
)


def make_finding(identifier, **overrides):
    finding = {
        "id": identifier,
        "rule_id": "PUBLIC_ACCESS",
        "resource": "sample-storage",
        "severity": "high",
        "exposure": "public",
        "data_sensitivity": "sensitive",
        "exploitability": "high",
    }
    finding.update(overrides)
    return finding


class TestRiskAnalyzer(unittest.TestCase):

    def test_critical_risk_score(self):
        result = analyse_finding(make_finding("F-001"))
        self.assertEqual(result["risk_score"], 90)
        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_low_risk_score(self):
        finding = make_finding(
            "F-002",
            severity="low",
            exposure="internal",
            data_sensitivity="normal",
            exploitability="low",
        )
        result = analyse_finding(finding)
        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(result["risk_level"], "LOW")

    def test_highest_risk_comes_first(self):
        low = make_finding(
            "LOW",
            severity="low",
            exposure="internal",
            data_sensitivity="normal",
            exploitability="low",
        )
        high = make_finding("HIGH")

        results = prioritise_findings([low, high])

        self.assertEqual(
            [item["id"] for item in results],
            ["HIGH", "LOW"],
        )

    def test_encryption_recommendation(self):
        finding = make_finding(
            "F-003",
            rule_id="ENCRYPTION_DISABLED",
        )
        result = analyse_finding(finding)
        self.assertIn(
            "Enable encryption",
            result["recommendation"],
        )

    def test_original_finding_is_unchanged(self):
        finding = make_finding("F-004")
        original = finding.copy()

        analyse_finding(finding)

        self.assertEqual(finding, original)

    def test_invalid_severity_is_rejected(self):
        finding = make_finding("F-005", severity="urgent")

        with self.assertRaises(ValueError):
            analyse_finding(finding)

    def test_missing_field_is_rejected(self):
        finding = make_finding("F-006")
        del finding["exposure"]

        with self.assertRaises(ValueError):
            analyse_finding(finding)


if __name__ == "__main__":
    unittest.main()
