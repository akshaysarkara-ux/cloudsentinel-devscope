"""CloudSentinel: local Terraform security scanner."""

import re
from pathlib import Path


def scan_terraform_file(file_path):
    """Scan a local Terraform file for basic security risks."""

    path = Path(file_path)

    if not path.is_file() or path.suffix.lower() != ".tf":
        raise ValueError("Please provide a valid .tf file.")

    content = path.read_text(encoding="utf-8")
    findings = []

    checks = [
        (
            "BLOCK_PUBLIC_ACLS",
            r"\bblock_public_acls\s*=\s*false\b",
            "PUBLIC_ACCESS",
            "High",
            "Public ACL blocking is disabled.",
        ),
        (
            "BLOCK_PUBLIC_POLICY",
            r"\bblock_public_policy\s*=\s*false\b",
            "PUBLIC_ACCESS",
            "High",
            "Public policy blocking is disabled.",
        ),
        (
            "IGNORE_PUBLIC_ACLS",
            r"\bignore_public_acls\s*=\s*false\b",
            "PUBLIC_ACCESS",
            "High",
            "Ignoring public ACLs is disabled.",
        ),
        (
            "RESTRICT_PUBLIC_BUCKETS",
            r"\brestrict_public_buckets\s*=\s*false\b",
            "PUBLIC_ACCESS",
            "High",
            "Restricting public bucket access is disabled.",
        ),
        (
            "VERSIONING_DISABLED",
            r"\bversioning\s*\{[^}]*\benabled\s*=\s*false\b",
            "VERSIONING_DISABLED",
            "Medium",
            "Storage versioning is disabled.",
        ),
        (
            "VERSIONING_STATUS_DISABLED",
            r'\bversioning\s*\{[^}]*\bstatus\s*=\s*"Disabled"',
            "VERSIONING_DISABLED",
            "Medium",
            "Storage versioning is disabled.",
        ),
    ]

    for check_id, pattern, rule_id, severity, message in checks:
        if re.search(pattern, content, re.IGNORECASE):
            is_public_access = rule_id == "PUBLIC_ACCESS"

            findings.append({
                "id": f"TF-{len(findings) + 1:03}",
                "check_id": check_id,
                "rule_id": rule_id,
                "severity": severity,
                "exposure": (
                    "public" if is_public_access else "internal"
                ),
                "data_sensitivity": "normal",
                "exploitability": (
                    "high" if is_public_access else "medium"
                ),
                "resource": path.name,
                "message": message,
            })

    return findings