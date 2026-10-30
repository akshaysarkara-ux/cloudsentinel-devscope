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

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
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
        finding["exposure"],
        {"public", "internal"},
        "exposure",
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


def _priority_key(item):
    """Order findings using risk score and additional risk factors."""

    return (
        item["risk_score"],
        item["score_breakdown"]["public_exposure"],
        item["score_breakdown"]["sensitive_data"],
        SEVERITY_ORDER[item["severity"].strip().lower()],
        item["score_breakdown"]["exploitability"],
    )


def _explain_priority(item):
    """Explain why a finding deserves its priority."""

    reasons = []

    if item["exposure"].strip().lower() == "public":
        reasons.append("the resource is publicly exposed")

    if item["data_sensitivity"].strip().lower() == "sensitive":
        reasons.append("sensitive data may be at risk")

    severity = item["severity"].strip().lower()

    if severity == "critical":
        reasons.append("the finding has critical severity")
    elif severity == "high":
        reasons.append("the finding has high severity")
    elif severity == "medium":
        reasons.append("the finding has medium severity")

    if item["exploitability"].strip().lower() == "high":
        reasons.append("the issue has high exploitability")
    elif item["exploitability"].strip().lower() == "medium":
        reasons.append("the issue has medium exploitability")

    if not reasons:
        reasons.append(
            "its risk score and other risk factors determine "
            "its position"
        )

    return "Prioritised because " + "; ".join(reasons) + "."


def _identify_related_findings(findings):
    """Identify findings sharing the same resource and security rule."""

    groups = {}

    for item in findings:
        resource = str(
            item.get("resource", "unknown")
        ).strip().lower()
        rule_id = str(
            item.get("rule_id", "unknown")
        ).strip().upper()

        group_key = (resource, rule_id)
        groups.setdefault(group_key, []).append(item)

    for group in groups.values():
        related_ids = [
            str(other.get("check_id", other.get("id", "Unknown")))
            for other in group
        ]

        for item in group:
            item["related_finding_count"] = len(group)
            item["related_findings"] = [
                related_id
                for other, related_id in zip(group, related_ids)
                if other["id"] != item["id"]
            ]

    return findings


def prioritise_findings(findings):
    """Rank findings and explain which should be fixed first."""

    if not isinstance(findings, (list, tuple)):
        raise ValueError("findings must be a list or tuple.")

    results = [analyse_finding(item) for item in findings]

    # Add context about related findings without changing their scores.
    _identify_related_findings(results)

    # Higher risk scores come first. Additional factors break ties.
    ranked = sorted(
        results,
        key=_priority_key,
        reverse=True,
    )

    for index, item in enumerate(ranked, start=1):
        if index == 1:
            priority = "FIX FIRST"
        elif index == 2:
            priority = "FIX NEXT"
        else:
            priority = "FIX AFTER HIGHER PRIORITIES"

        item["priority_rank"] = index
        item["priority"] = priority
        item["priority_reason"] = _explain_priority(item)

    return ranked


if __name__ == "__main__":
    sample_findings = [
        {
            "id": "F-001",
            "check_id": "BLOCK_PUBLIC_ACLS",
            "rule_id": "PUBLIC_ACCESS",
            "resource": "example-storage",
            "severity": "high",
            "exposure": "public",
            "data_sensitivity": "sensitive",
            "exploitability": "high",
        },
        {
            "id": "F-002",
            "check_id": "VERSIONING_DISABLED",
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
            f'{finding["priority_rank"]}. '
            f'{finding["priority"]}: {finding["id"]}'
        )
        print(
            f'   Risk: {finding["risk_level"]} '
            f'({finding["risk_score"]}/100)'
        )
        print(
            f'   Related findings: '
            f'{finding["related_finding_count"]}'
        )
        print(f'   Why: {finding["priority_reason"]}')
        print(f'   Fix: {finding["recommendation"]}')
        print()