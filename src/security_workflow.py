from src.risk_analyzer import prioritise_findings
from src.remediation import remediate_storage_config


def run_security_workflow(findings, storage_config):
    """
    Rank security findings and simulate storage remediation.
    No real cloud resources are changed.
    """
    prioritised_findings = prioritise_findings(findings)

    remediation_result = remediate_storage_config(storage_config)

    return {
        "prioritised_findings": prioritised_findings,
        "remediation_result": remediation_result,
    }
