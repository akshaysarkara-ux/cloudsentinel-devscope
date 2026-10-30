from src.risk_analyzer import prioritise_findings
from src.remediation import remediate_storage_config
from src.report_generator import generate_security_report


def run_security_workflow(findings, storage_config):
    """
    Rank security findings, simulate storage remediation,
    verify the result, and generate a security report.

    No real cloud resources are changed.
    """

    # Step 1: Analyse and prioritise security findings
    prioritised_findings = prioritise_findings(findings)

    # Step 2: Simulate storage remediation and verify the result
    remediation_result = remediate_storage_config(storage_config)

    # Step 3: Generate a report using the analysis and remediation results
    report = generate_security_report(
        prioritised_findings,
        remediation_result,
    )

    # Step 4: Return the complete workflow results
    return {
        "prioritised_findings": prioritised_findings,
        "remediation_result": remediation_result,
        "verification_passed": remediation_result["verification_passed"],
        "verification_message": remediation_result["verification_message"],
        "report": report,
    }