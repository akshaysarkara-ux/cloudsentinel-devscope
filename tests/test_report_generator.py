import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from src.report_generator import (
    generate_security_report,
    save_json_report,
    print_security_report,
)


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.findings = [
            {
                "id": "TEST-001",
                "risk_level": "HIGH",
                "risk_score": 75,
                "recommendation": "Disable public access.",
            }
        ]

        self.remediation = {
            "status": "REMEDIATED",
            "message": "Public access disabled in the simulation.",
        }

    def test_generate_report(self):
        report = generate_security_report(
            self.findings, self.remediation
        )

        self.assertEqual(report["project"], "CloudSentinel")
        self.assertEqual(report["total_findings"], 1)
        self.assertEqual(report["findings"], self.findings)
        self.assertIn("simulated", report["safety_note"].lower())

    def test_save_json_report(self):
        report = generate_security_report(
            self.findings, self.remediation
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"
            saved_path = save_json_report(report, str(output_path))

            with open(saved_path, encoding="utf-8") as file:
                loaded_report = json.load(file)

            self.assertEqual(loaded_report["total_findings"], 1)
            self.assertEqual(
                loaded_report["findings"][0]["id"], "TEST-001"
            )

    def test_print_security_report(self):
        report = generate_security_report(
            self.findings, self.remediation
        )
        output = StringIO()

        with redirect_stdout(output):
            print_security_report(report)

        printed_text = output.getvalue()

        self.assertIn("CLOUDSENTINEL SECURITY REPORT", printed_text)
        self.assertIn("TEST-001", printed_text)
        self.assertIn("HIGH", printed_text)
        self.assertIn("No real cloud resources were modified", printed_text)


if __name__ == "__main__":
    unittest.main()
