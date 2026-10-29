"""CloudSentinel: explainable cloud security risk analysis."""

from copy import deepcopy

SEVERITY_POINTS = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 0,
}

EXPLOITABILITY_POINTS = {
    "high": 15,
    "medium": 8,
    "low": 0,
}

RECOMMENDATIONS = {
    "PUBLIC_ACCESS": (
        "Block public access and review storage access policies."
    ),
    "ENCRYPTION_DISABLED": (
        "Enable encryption at rest using an approved method."
    ),
    "LOGGING_DISABLED": (
        "Enable access logging and protect the log destination."
    ),
    "VERSIONING_DISABLED": (
        "Enable versioning to help recover deleted or changed data."
    ),
}


def _normalise(value, allowed, field_name):
    """Validate and standardise a finding value."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")

    value = value.strip().lower()

    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValueError(
            f"Unsupported {field_name}: {value!r}. "
            f"Allowed values: {choices}"
        )

    return value


def analyse_finding(finding):
    """Calculate a risk score and explain the result."""

    if not isinstance(finding, dict):
        raise ValueError("Each finding must be a dictionary.")

    required = (
        "id",
        "severity",
        "exposure",
        "data_sensitivity",
        "exploitability",
    )

    missing = [key for key in required if key not in finding]

    if missing:
        raise ValueError(
            "Missing required fields: " + ", ".join(missing)
        )

    severity = _normalise(
        finding["severity"], SEVERITY_POINTS, "severity"
    )
    exposure = _normalise(
        finding["exposure"], {"public", "internal"}, "exposure"
    )
    sensitivity = _normalise(
        finding["data_sensitivity"],
        {"sensitive", "normal"},
        "data_sensitivity",
    )
    exploitability = _normalise(
        finding["exploitability"],
        EXPLOITABILITY_POINTS,
        "exploitability",
    )

    breakdown = {
        "severity": SEVERITY_POINTS[severity],
        "public_exposure": 25 if exposure == "public" else 0,
        "sensitive_data": 20 if sensitivity == "sensitive" else 0,
        "exploitability": EXPLOITABILITY_POINTS[exploitability],
    }

    score = min(100, sum(breakdown.values()))

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    rule_id = str(finding.get("rule_id", "")).strip().upper()

    result = deepcopy(finding)
    result.update({
        "risk_score": score,
        "risk_level": level,
        "score_breakdown": breakdown,
        "recommendation": RECOMMENDATIONS.get(
            rule_id,
            "Review the finding and apply the appropriate "
            "secure configuration guidance.",
        ),
    })

    return result


def prioritise_findings(findings):
    """Sort findings from highest risk score to lowest."""

    if not isinstance(findings, (list, tuple)):
        raise ValueError("findings must be a list or tuple.")

    results = [analyse_finding(item) for item in findings]

    return sorted(
        results,
        key=lambda item: item["risk_score"],
        reverse=True,
    )


if __name__ == "__main__":
    sample_findings = [
        {
            "id": "F-001",
            "rule_id": "PUBLIC_ACCESS",
            "resource": "example-storage",
            "severity": "high",
            "exposure": "public",
            "data_sensitivity": "sensitive",
            "exploitability": "high",
        },
        {
            "id": "F-002",
            "rule_id": "VERSIONING_DISABLED",
            "resource": "internal-backup",
            "severity": "medium",
            "exposure": "internal",
            "data_sensitivity": "normal",
            "exploitability": "low",
        },
    ]

    for finding in prioritise_findings(sample_findings):
        print(
            f'{finding["id"]}: {finding["risk_level"]} '
            f'({finding["risk_score"]}/100)'
        )
        print(f'  Fix: {finding["recommendation"]}')
