import json
from pathlib import Path


def generate_security_report(findings, remediation_result):
    """
    Generate a readable CloudSentinel security report.
    The report uses analysis results and simulated remediation only.
    """

    report = {
        "project": "CloudSentinel",
        "report_type": "Cloud Security Assessment",
        "total_findings": len(findings),
        "findings": findings,
        "remediation": remediation_result,
        "safety_note": (
            "Remediation is simulated locally. "
            "No real cloud resources were modified."
        ),
    }

    return report


def save_json_report(report, output_path="reports/security_report.json"):
    """Save the report as a JSON file."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return str(path)


def print_security_report(report):
    """Print a readable summary in the terminal."""

    print("=" * 50)
    print("           CLOUDSENTINEL SECURITY REPORT")
    print("=" * 50)
    print(f"Total findings: {report['total_findings']}")

    for finding in report["findings"]:
        print(
            f"\nID: {finding.get('id', 'N/A')}"
            f"\nRisk: {finding.get('risk_level', 'Unassessed')}"
            f"\nScore: {finding.get('risk_score', 'N/A')}"
            f"\nRecommendation: "
            f"{finding.get('recommendation', 'Review manually')}"
        )

    remediation = report["remediation"]
    print("\n--- Simulated Remediation ---")
    print(f"Status: {remediation.get('status', 'Not run')}")
    print(f"Message: {remediation.get('message', 'No details')}")
    print("\nNo real cloud resources were modified.")
    print("=" * 50)
