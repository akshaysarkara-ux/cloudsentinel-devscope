"""CloudSentinel: Local cloud security intelligence dashboard."""

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from src.security_workflow import run_security_workflow
from src.terraform_scanner import scan_terraform_file
from src.risk_analyzer import prioritise_findings


# ==================================================
# Page configuration
# ==================================================

st.set_page_config(
    page_title="CloudSentinel",
    page_icon="🛡️",
    layout="wide",
)


# ==================================================
# Demonstration data
# ==================================================

SAMPLE_FINDINGS = [
    {
        "id": "DEMO-001",
        "check_id": "PUBLIC_STORAGE_EXPOSURE",
        "rule_id": "PUBLIC_ACCESS",
        "resource": "demo-storage",
        "severity": "critical",
        "exposure": "public",
        "data_sensitivity": "sensitive",
        "exploitability": "high",
        "message": "Storage may expose sensitive information.",
    },
    {
        "id": "DEMO-002",
        "check_id": "ENCRYPTION_REVIEW",
        "rule_id": "ENCRYPTION_DISABLED",
        "resource": "demo-database",
        "severity": "medium",
        "exposure": "internal",
        "data_sensitivity": "sensitive",
        "exploitability": "medium",
        "message": "Review encryption settings.",
    },
    {
        "id": "DEMO-003",
        "check_id": "LOGGING_REVIEW",
        "rule_id": "LOGGING_DISABLED",
        "resource": "demo-application",
        "severity": "low",
        "exposure": "internal",
        "data_sensitivity": "normal",
        "exploitability": "low",
        "message": "Review access logging configuration.",
    },
]

SAMPLE_STORAGE_CONFIG = {
    "public_access": True,
}


# ==================================================
# Helper functions
# ==================================================

def safe_value(value):
    """Convert values into display-friendly text."""
    if value is None:
        return "Not available"
    return str(value)


def related_findings_section(
    findings,
    title="Related Security Findings",
):
    """Group findings sharing the same resource and rule."""

    st.subheader(f"🔗 {title}")
    st.caption(
        "Checks are grouped when they share a resource and security "
        "rule. Grouping helps investigation but does not prove that "
        "the findings are duplicate vulnerabilities."
    )

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

    related_groups = [
        (key, items)
        for key, items in groups.items()
        if len(items) > 1
    ]

    if not related_groups:
        st.info(
            "No findings sharing both a resource and a security rule "
            "were identified."
        )
        return

    for (resource, rule_id), items in related_groups:
        with st.expander(
            f"{resource} — {rule_id} "
            f"({len(items)} related checks)"
        ):
            for item in items:
                check_id = item.get(
                    "check_id",
                    item.get("id", "Unknown"),
                )

                message = item.get(
                    "message",
                    "No description available.",
                )

                st.write(f"**{check_id}** — {message}")


def display_findings_table(findings, key_prefix="findings"):
    """Display ranked findings in a table."""

    if not findings:
        st.info("No security findings were detected.")
        return

    table_data = []

    for index, item in enumerate(findings, start=1):
        table_data.append({
            "Priority": item.get("priority_rank", index),
            "Priority Decision": item.get("priority", "REVIEW"),
            "Finding ID": item.get("id", "Unknown"),
            "Check ID": item.get("check_id", "Not provided"),
            "Rule ID": item.get("rule_id", "Unknown"),
            "Resource": item.get("resource", "Unknown"),
            "Severity": safe_value(
                item.get("severity")
            ).upper(),
            "Risk Level": item.get("risk_level", "Unknown"),
            "Risk Score": item.get("risk_score", 0),
            "Why This Priority": item.get(
                "priority_reason",
                "Review the risk factors.",
            ),
            "Recommendation": item.get(
                "recommendation",
                "Review the security configuration.",
            ),
        })

    st.dataframe(
        pd.DataFrame(table_data),
        use_container_width=True,
        hide_index=True,
        key=f"{key_prefix}_table",
    )


def display_finding_explanations(
    findings,
    title="Sample Security Decisions",
    key_prefix="sample",
):
    """Explain a selected finding using a uniquely keyed selector."""

    st.subheader(f"🔍 {title}")

    if not findings:
        st.info("There are no findings to explain.")
        return

    labels = []

    for index, item in enumerate(findings):
        identifier = item.get(
            "check_id",
            item.get("id", "Unknown"),
        )

        score = item.get("risk_score", 0)
        level = item.get("risk_level", "Unknown")

        labels.append(
            f"{identifier} — {level} ({score}/100)"
        )

    selected_index = st.selectbox(
        "Select a finding to investigate",
        options=list(range(len(findings))),
        format_func=lambda index: labels[index],
        key=f"finding_explanation_selection_{key_prefix}",
    )

    item = findings[selected_index]

    st.write(f"**Finding:** {item.get('id', 'Unknown')}")
    st.write(
        f"**Check ID:** {item.get('check_id', 'Not provided')}"
    )
    st.write(
        f"**Rule ID:** {item.get('rule_id', 'Unknown')}"
    )
    st.write(
        f"**Resource:** {item.get('resource', 'Unknown')}"
    )
    st.write(
        f"**Severity:** {safe_value(item.get('severity')).upper()}"
    )
    st.write(
        f"**Risk level:** {item.get('risk_level', 'Unknown')}"
    )
    st.write(
        f"**Risk score:** {item.get('risk_score', 0)}/100"
    )
    st.write(
        f"**Priority decision:** {item.get('priority', 'REVIEW')}"
    )
    st.write(
        f"**Why this priority:** "
        f"{item.get('priority_reason', 'Not available')}"
    )
    st.write(
        f"**Recommendation:** "
        f"{item.get('recommendation', 'Review the configuration.')}"
    )

    related_count = item.get("related_finding_count")

    if related_count is not None:
        st.write(f"**Related findings:** {related_count}")

    related_ids = item.get("related_findings", [])

    if related_ids:
        st.write(
            "**Related check IDs:** " + ", ".join(related_ids)
        )

    breakdown = item.get("score_breakdown")

    if isinstance(breakdown, dict):
        st.write("**Risk score breakdown**")

        breakdown_rows = [
            {
                "Risk factor": str(key).replace("_", " ").title(),
                "Points": value,
            }
            for key, value in breakdown.items()
        ]

        st.dataframe(
            pd.DataFrame(breakdown_rows),
            use_container_width=True,
            hide_index=True,
            key=f"risk_breakdown_{key_prefix}",
        )


def report_to_text(report):
    """Convert report data into downloadable text."""

    if isinstance(report, (dict, list)):
        return json.dumps(report, indent=2, default=str)

    return safe_value(report)


# ==================================================
# Dashboard header
# ==================================================

st.markdown(
    """
    <style>
    .project-banner {
        padding: 24px;
        border-radius: 14px;
        background: linear-gradient(120deg, #14243a, #123047);
        border: 1px solid #31516a;
        margin-bottom: 20px;
    }

    .project-banner h1 {
        margin-bottom: 6px;
        color: #f8fafc;
    }

    .project-tagline {
        font-size: 18px;
        color: #cbd5e1;
    }

    .project-status {
        margin-top: 12px;
        color: #7dd3fc;
        font-size: 12px;
        letter-spacing: 1px;
    }
    </style>

    <div class="project-banner">
        <h1>🛡️ CloudSentinel</h1>
        <div class="project-tagline">
            Cloud Security Intelligence Platform
        </div>
        <div class="project-status">
            RISK ANALYSIS • DECISION SUPPORT • SIMULATED REMEDIATION
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.caption(
    "Educational DevSecOps project | Local simulation | No AWS connection"
)

st.info(
    "CloudSentinel scans supported Terraform security patterns, "
    "prioritises risks, explains decisions, and demonstrates "
    "simulated remediation. It does not deploy resources or modify "
    "cloud configurations."
)


# ==================================================
# Sidebar
# ==================================================

st.sidebar.title("🛡️ CloudSentinel")
st.sidebar.caption("Security Control Panel")
st.sidebar.divider()
st.sidebar.write("**Operating mode**")
st.sidebar.success("Local simulation")
st.sidebar.write("**Cloud connection:** None")
st.sidebar.write("**Deployment:** Disabled")
st.sidebar.write("**Cloud resource cost:** None required")
st.sidebar.divider()
st.sidebar.caption("Terraform scanning runs locally.")


# ==================================================
# Sample security analysis
# ==================================================

st.header("📊 Sample Security Analysis")

st.write(
    "Run the demonstration dataset to see risk scoring, prioritisation, "
    "related findings, simulated remediation, and report generation."
)

if st.button(
    "▶ Run Security Analysis",
    type="primary",
    key="run_sample_security_analysis",
):
    try:
        results = run_security_workflow(
            SAMPLE_FINDINGS,
            SAMPLE_STORAGE_CONFIG,
        )

        st.session_state["security_results"] = results
        st.success("Sample security analysis completed.")

    except Exception as exc:
        st.error(f"Sample analysis failed: {exc}")


results = st.session_state.get("security_results")

if results:
    findings = results.get("prioritised_findings", [])
    remediation = results.get("remediation_result", {})
    report = results.get("report", "")

    st.divider()
    st.header("📊 Security Overview")

    critical_count = sum(
        item.get("risk_level") == "CRITICAL"
        for item in findings
    )

    high_count = sum(
        item.get("risk_level") == "HIGH"
        for item in findings
    )

    medium_count = sum(
        item.get("risk_level") == "MEDIUM"
        for item in findings
    )

    low_count = sum(
        item.get("risk_level") == "LOW"
        for item in findings
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Findings", len(findings))
    col2.metric("Critical Risks", critical_count)
    col3.metric("High Risks", high_count)
    col4.metric("Medium / Low", medium_count + low_count)

    st.divider()
    st.header("🎯 Risk Prioritisation")

    st.write(
        "Findings are ranked using severity, exposure, data sensitivity, "
        "and exploitability. Higher-risk findings receive higher priority."
    )

    display_findings_table(
        findings,
        key_prefix="sample_findings",
    )

    related_findings_section(
        findings,
        title="Related Sample Findings",
    )

    display_finding_explanations(
        findings,
        title="Sample Security Decisions",
        key_prefix="sample",
    )

    st.divider()
    st.header("🧰 Simulated Remediation")

    st.caption(
        "This is a simulation. It does not change any AWS settings "
        "or real cloud resources."
    )

    if isinstance(remediation, dict):
        for key, value in remediation.items():
            st.write(
                f"**{key.replace('_', ' ').title()}:** {value}"
            )
    else:
        st.write(safe_value(remediation))

    st.divider()
    st.header("📄 Sample Security Report")

    st.download_button(
        "⬇ Download Sample Security Report",
        data=report_to_text(report),
        file_name="cloudsentinel_security_report.txt",
        mime="text/plain",
        key="download_sample_security_report",
    )


# ==================================================
# Local Terraform security scanner
# ==================================================

st.divider()
st.header("📁 Local Terraform Security Scanner")

st.write(
    "Upload a Terraform `.tf` file to inspect supported security "
    "patterns. The file is scanned locally."
)

uploaded_file = st.file_uploader(
    "Choose a Terraform file",
    type=["tf"],
    key="terraform_upload",
)

if uploaded_file is not None:
    if st.button(
        "🔎 Scan Terraform File",
        type="primary",
        key="scan_terraform_file",
    ):
        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".tf",
                delete=False,
            ) as temporary_file:
                temporary_file.write(uploaded_file.getvalue())
                temporary_path = Path(temporary_file.name)

            raw_findings = scan_terraform_file(temporary_path)

            # Display the original uploaded filename, not the
            # temporary filename used for local scanning.
            for finding in raw_findings:
                finding["resource"] = uploaded_file.name

            if raw_findings:
                ranked_findings = prioritise_findings(raw_findings)

                st.session_state["terraform_findings"] = ranked_findings
                st.session_state["terraform_filename"] = uploaded_file.name

                st.success(
                    f"Scan completed. Found {len(ranked_findings)} "
                    "security finding(s)."
                )

            else:
                st.session_state["terraform_findings"] = []
                st.session_state["terraform_filename"] = uploaded_file.name

                st.success(
                    "No supported security issues were detected "
                    "by the current scanner."
                )

        except Exception as exc:
            st.error(f"Terraform scan failed: {exc}")

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


# ==================================================
# Terraform results
# ==================================================

terraform_findings = st.session_state.get("terraform_findings")

if terraform_findings is not None:
    filename = st.session_state.get(
        "terraform_filename",
        "uploaded-file.tf",
    )

    st.subheader(f"Results for {filename}")

    if terraform_findings:
        display_findings_table(
            terraform_findings,
            key_prefix="terraform_findings",
        )

        related_findings_section(
            terraform_findings,
            title="Related Terraform Findings",
        )

        display_finding_explanations(
            terraform_findings,
            title="Terraform Security Decisions",
            key_prefix="terraform",
        )

        csv_rows = []

        for item in terraform_findings:
            csv_rows.append({
                "Finding ID": item.get("id", ""),
                "Check ID": item.get("check_id", ""),
                "Rule ID": item.get("rule_id", ""),
                "Resource": item.get("resource", ""),
                "Severity": item.get("severity", ""),
                "Risk Level": item.get("risk_level", ""),
                "Risk Score": item.get("risk_score", ""),
                "Priority": item.get("priority", ""),
                "Why This Priority": item.get("priority_reason", ""),
                "Recommendation": item.get("recommendation", ""),
            })

        csv_data = pd.DataFrame(csv_rows).to_csv(index=False)

        st.download_button(
            "⬇ Download Terraform Findings (CSV)",
            data=csv_data,
            file_name="cloudsentinel_terraform_findings.csv",
            mime="text/csv",
            key="download_terraform_findings_csv",
        )

        report_data = {
            "project": "CloudSentinel",
            "scan_type": "Local Terraform scan",
            "filename": filename,
            "finding_count": len(terraform_findings),
            "findings": terraform_findings,
        }

        st.download_button(
            "⬇ Download Terraform Security Report (JSON)",
            data=json.dumps(report_data, indent=2, default=str),
            file_name="cloudsentinel_terraform_report.json",
            mime="application/json",
            key="download_terraform_security_report",
        )

    else:
        st.success(
            "No supported security issues were detected by the "
            "current scanner. This does not guarantee that the file "
            "is completely secure."
        )


# ==================================================
# Footer
# ==================================================

st.divider()

st.caption(
    "CloudSentinel | Educational security decision-support prototype | "
    "Local-only operation | No AWS deployment"
)