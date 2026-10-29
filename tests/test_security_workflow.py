import unittest

from src.security_workflow import run_security_workflow


class TestSecurityWorkflow(unittest.TestCase):

    def test_prioritises_risks_and_simulates_remediation(self):
        findings = [
            {
                "id": "LOW-001",
                "rule_id": "PUBLIC_ACCESS",
                "resource": "internal-storage",
                "severity": "low",
                "exposure": "internal",
                "data_sensitivity": "normal",
                "exploitability": "low",
            },
            {
                "id": "HIGH-001",
                "rule_id": "PUBLIC_ACCESS",
                "resource": "public-storage",
                "severity": "high",
                "exposure": "public",
                "data_sensitivity": "sensitive",
                "exploitability": "high",
            },
        ]

        storage_config = {
            "resource": "example-storage",
            "public_access": True,
        }

        result = run_security_workflow(findings, storage_config)

        ranked = result["prioritised_findings"]
        remediation = result["remediation_result"]
        report = result["report"]

        # Check risk prioritisation.
        self.assertEqual(ranked[0]["id"], "HIGH-001")
        self.assertEqual(ranked[1]["id"], "LOW-001")

        # Check simulated remediation.
        self.assertEqual(remediation["public_access"], False)
        self.assertEqual(remediation["status"], "REMEDIATED")

        # Check report generation and integration.
        self.assertEqual(report["project"], "CloudSentinel")
        self.assertEqual(report["total_findings"], 2)
        self.assertEqual(
            report["findings"][0]["id"], "HIGH-001"
        )
        self.assertEqual(
            report["remediation"]["status"], "REMEDIATED"
        )
        self.assertIn("simulated", report["safety_note"].lower())

        # The original configuration must remain unchanged.
        self.assertTrue(storage_config["public_access"])


if __name__ == "__main__":
    unittest.main()
