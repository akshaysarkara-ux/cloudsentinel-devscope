import json
from pathlib import Path
from datetime import datetime


def generate_security_report(findings, remediation_result):
    """Generate a detailed CloudSentinel security report."""

    risk_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        level = str(finding.get("risk_level", "UNKNOWN")).upper()

        if level in risk_distribution:
            risk_distribution[level] += 1

    total_findings = len(findings)

    if risk_distribution["CRITICAL"] > 0:
        overall_status = "CRITICAL RISK"
    elif risk_distribution["HIGH"] > 0:
        overall_status = "HIGH RISK"
    elif risk_distribution["MEDIUM"] > 0:
        overall_status = "MODERATE RISK"
    elif total_findings > 0:
        overall_status = "LOW RISK"
    else:
        overall_status = "NO FINDINGS DETECTED"

    # Enhanced finding details
    finding_details = []

    for finding in findings:
        finding_details.append({
            "priority": finding.get("priority", "N/A"),
            "id": finding.get("id", "N/A"),
            "finding_id": finding.get(
                "finding_id",
                finding.get("id", "N/A")
            ),
            "resource": finding.get("resource", "Unknown"),
            "rule_id": finding.get("rule_id", "Unknown"),
            "severity": finding.get("severity", "Unknown"),
            "risk_level": finding.get("risk_level", "Unassessed"),
            "risk_score": finding.get("risk_score", "N/A"),
            "priority_decision": finding.get(
                "priority_decision", "Not available"
            ),
            "priority_reason": finding.get(
                "priority_reason", "No explanation available"
            ),
            "exposure": finding.get("exposure", "Unknown"),
            "data_sensitivity": finding.get(
                "data_sensitivity", "Unknown"
            ),
            "exploitability": finding.get(
                "exploitability", "Unknown"
            ),
            "recommendation": finding.get(
                "recommendation", "Review manually"
            ),
        })

    # Remediation details
    remediation_details = {
        "status": remediation_result.get("status", "Not run"),
        "message": remediation_result.get("message", "No details"),
        "verification_passed": remediation_result.get(
            "verification_passed", False
        ),
        "verification_message": remediation_result.get(
            "verification_message", "Verification not available"
        ),
        "before_configuration": remediation_result.get(
            "original_config", {}
        ),
        "after_configuration": {
            key: value
            for key, value in remediation_result.items()
            if key not in [
                "original_config",
                "changes",
                "verification_passed",
                "verification_message",
            ]
        },
        "changes": remediation_result.get("changes", []),
    }

    report = {
        "project": "CloudSentinel",
        "report_type": "Cloud Security Assessment",
        "generated_at": datetime.now().astimezone().isoformat(),

        "security_summary": {
            "overall_status": overall_status,
            "total_findings": total_findings,
            "risk_distribution": risk_distribution,
        },

        "total_findings": total_findings,

        # Preserve original findings for compatibility with existing tests.
        "findings": findings,

        # Store enhanced information separately.
        "finding_details": finding_details,

        "remediation": remediation_details,

        "verification": {
            "passed": remediation_details["verification_passed"],
            "message": remediation_details["verification_message"],
        },

        "safety_note": (
            "Remediation is simulated locally. "
            "No real cloud resources were modified."
        ),
    }

    return report


def save_json_report(
    report,
    output_path="reports/security_report.json"
):
    """Save the report as a JSON file."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, default=str)

    return str(path)


def print_security_report(report):
    """Print a readable security report in the terminal."""

    print("=" * 60)
    print("             CLOUDSENTINEL SECURITY REPORT")
    print("=" * 60)

    print(f"Generated: {report.get('generated_at', 'N/A')}")

    summary = report.get("security_summary", {})

    print("\n--- Security Summary ---")
    print(f"Overall Status: {summary.get('overall_status', 'N/A')}")
    print(f"Total Findings: {report.get('total_findings', 0)}")

    print("\n--- Risk Distribution ---")

    for level, count in summary.get(
        "risk_distribution", {}
    ).items():
        print(f"{level}: {count}")

    print("\n--- Prioritised Security Findings ---")

    # Use enhanced details while preserving the original findings.
    findings_to_print = report.get(
        "finding_details",
        report.get("findings", [])
    )

    for finding in findings_to_print:

        print("\n" + "-" * 45)
        print(f"Priority: {finding.get('priority', 'N/A')}")
        print(f"ID: {finding.get('id', 'N/A')}")
        print(f"Resource: {finding.get('resource', 'Unknown')}")
        print(f"Rule: {finding.get('rule_id', 'Unknown')}")
        print(f"Risk Level: {finding.get('risk_level', 'N/A')}")
        print(f"Risk Score: {finding.get('risk_score', 'N/A')}")

        print(
            f"Priority Decision: "
            f"{finding.get('priority_decision', 'N/A')}"
        )

        print(
            f"Why This Priority: "
            f"{finding.get('priority_reason', 'N/A')}"
        )

        print(
            f"Recommendation: "
            f"{finding.get('recommendation', 'N/A')}"
        )

    remediation = report.get("remediation", {})

    print("\n--- Simulated Remediation ---")
    print(f"Status: {remediation.get('status', 'Not run')}")
    print(f"Message: {remediation.get('message', 'No details')}")

    print("\n--- Independent Verification ---")
    print(
        f"Verification Passed: "
        f"{remediation.get('verification_passed', False)}"
    )
    print(
        f"Verification Message: "
        f"{remediation.get('verification_message', 'N/A')}"
    )

    print("\n--- Configuration Changes ---")

    changes = remediation.get("changes", [])

    if changes:
        for change in changes:
            print(
                f"{change.get('setting', 'Unknown')}: "
                f"{change.get('before')} -> "
                f"{change.get('after')}"
            )
    else:
        print("No configuration changes recorded.")

    print("\n--- Safety Information ---")
    print(report.get("safety_note", "No safety information available."))

    print("=" * 60)