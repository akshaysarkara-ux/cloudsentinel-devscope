from src.risk_analyzer import prioritise_findings
from src.remediation import remediate_storage_config
from src.report_generator import generate_security_report


def run_security_workflow(findings, storage_config):
    """
    Rank security findings, simulate storage remediation,
    and generate a security report.

    No real cloud resources are changed.
    """
    prioritised_findings = prioritise_findings(findings)

    remediation_result = remediate_storage_config(storage_config)

    report = generate_security_report(
        prioritised_findings,
        remediation_result,
    )

    return {
        "prioritised_findings": prioritised_findings,
        "remediation_result": remediation_result,
        "report": report,
    }
