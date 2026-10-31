import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from src.security_workflow import run_security_workflow
from src.terraform_scanner import scan_terraform_file
from src.risk_analyzer import prioritise_findings


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="CloudSentinel",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CloudSentinel")
st.subheader("Explainable Cloud Security Risk Analysis")
st.write(
    "A local DevSecOps security tool that analyses Terraform "
    "configurations, prioritises risks, and simulates remediation."
)

st.info(
    "CloudSentinel runs locally. It does not connect to AWS "
    "or modify real cloud resources."
)


# --------------------------------------------------
# SAMPLE SECURITY FINDINGS
# --------------------------------------------------

sample_findings = [
    {
        "id": "DEMO-001",
        "finding_id": "DEMO-001",
        "check_id": "CKV_AWS_20",
        "rule_id": "PUBLIC_ACCESS",
        "resource": "demo-storage",
        "severity": "critical",
        "exposure": "public",
        "data_sensitivity": "sensitive",
        "exploitability": "high",
        "recommendation": "Disable public access to the storage resource.",
    },
    {
        "id": "DEMO-002",
        "finding_id": "DEMO-002",
        "check_id": "CKV_AWS_19",
        "rule_id": "ENCRYPTION_DISABLED",
        "resource": "demo-database",
        "severity": "medium",
        "exposure": "internal",
        "data_sensitivity": "sensitive",
        "exploitability": "medium",
        "recommendation": "Enable encryption for stored data.",
    },
    {
        "id": "DEMO-003",
        "finding_id": "DEMO-003",
        "check_id": "CKV_AWS_21",
        "rule_id": "LOGGING_DISABLED",
        "resource": "demo-storage",
        "severity": "low",
        "exposure": "internal",
        "data_sensitivity": "normal",
        "exploitability": "low",
        "recommendation": "Enable logging to improve monitoring.",
    },
]

sample_storage_config = {
    "resource": "demo-storage",
    "public_access": True,
}
# --------------------------------------------------
# HELPER: DISPLAY FINDINGS TABLE
# --------------------------------------------------

def display_findings_table(findings, key_prefix="findings"):

    if not findings:
        st.info("No findings to display.")
        return

    df = pd.DataFrame(findings)

    preferred_columns = [
        "priority",
        "priority_decision",
        "finding_id",
        "check_id",
        "rule_id",
        "resource",
        "severity",
        "risk_level",
        "risk_score",
        "priority_reason",
        "recommendation",
    ]

    columns = [
        column for column in preferred_columns
        if column in df.columns
    ]

    st.dataframe(
        df[columns],
        use_container_width=True,
        hide_index=True,
    )


# --------------------------------------------------
# HELPER: GROUP RELATED FINDINGS
# --------------------------------------------------

def related_findings_section(findings, title="Related Findings"):

    st.subheader(title)

    if not findings:
        st.info("No related findings available.")
        return

    groups = {}

    for finding in findings:
        resource = finding.get("resource", "Unknown")
        rule_id = finding.get("rule_id", "Unknown")

        group_key = (resource, rule_id)

        if group_key not in groups:
            groups[group_key] = []

        groups[group_key].append(finding)

    related_groups = {
        key: value
        for key, value in groups.items()
        if len(value) > 1
    }

    if not related_groups:
        st.caption(
            "No multiple findings were detected for the same "
            "resource and security rule."
        )
        return

    for (resource, rule_id), items in related_groups.items():

        with st.expander(
            f"{resource} — {rule_id} ({len(items)} findings)"
        ):
            for item in items:
                st.write(
                    f"- {item.get('finding_id', 'Unknown')} "
                    f"— {item.get('severity', 'Unknown')} severity"
                )


# --------------------------------------------------
# HELPER: EXPLAIN SECURITY DECISIONS
# --------------------------------------------------

def display_finding_explanations(
    findings,
    title="Security Decision Explanation",
    key_prefix="explanation",
):

    st.subheader(title)

    if not findings:
        st.info("No findings available for explanation.")
        return

    finding_labels = {}

    for index, finding in enumerate(findings):
        finding_id = finding.get(
            "finding_id",
            f"Finding {index + 1}",
        )

        finding_labels[f"{finding_id} — {finding.get('rule_id', 'Unknown')}"] = index

    selected_label = st.selectbox(
        "Select a finding to understand its priority",
        list(finding_labels.keys()),
        key=f"{key_prefix}_select",
    )

    selected = findings[finding_labels[selected_label]]

    st.write("**Finding:**", selected.get("finding_id", "Unknown"))
    st.write("**Resource:**", selected.get("resource", "Unknown"))
    st.write("**Severity:**", selected.get("severity", "Unknown"))
    st.write("**Risk level:**", selected.get("risk_level", "Not available"))
    st.write("**Risk score:**", selected.get("risk_score", "Not available"))

    st.write(
        "**Why this priority?**",
        selected.get(
            "priority_reason",
            "Priority is based on the risk analysis.",
        ),
    )

    st.write(
        "**Recommended action:**",
        selected.get("recommendation", "Review this finding."),
    )

    st.write("**Risk factors:**")

    factors = {
        "Public exposure": selected.get("public_exposure", False),
        "Sensitive data": selected.get("sensitive_data", False),
        "Exploitability": selected.get("exploitability", "Unknown"),
    }

    st.json(factors)


# --------------------------------------------------
# SAMPLE SECURITY ANALYSIS
# --------------------------------------------------

st.info("DEMO DATA — These are predefined sample findings for demonstration. They are not results from your uploaded Terraform file.")
st.divider()
st.header("🎯 Risk Prioritisation")

workflow = run_security_workflow(
    sample_findings,
    sample_storage_config,
)

findings = workflow["prioritised_findings"]

# Risk overview
critical_count = sum(
    1 for item in findings
    if item.get("risk_level") == "CRITICAL"
)

high_count = sum(
    1 for item in findings
    if item.get("risk_level") == "HIGH"
)

medium_count = sum(
    1 for item in findings
    if item.get("risk_level") == "MEDIUM"
)

low_count = sum(
    1 for item in findings
    if item.get("risk_level") == "LOW"
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Critical", critical_count)
col2.metric("High", high_count)
col3.metric("Medium", medium_count)
col4.metric("Low", low_count)


# --------------------------------------------------
# RISK DISTRIBUTION CHART
# --------------------------------------------------

st.subheader("📈 Risk Distribution")

risk_distribution = pd.DataFrame({
    "Risk Level": ["Critical", "High", "Medium", "Low"],
    "Number of Findings": [
        critical_count,
        high_count,
        medium_count,
        low_count,
    ],
}).set_index("Risk Level")

st.bar_chart(
    risk_distribution,
    y="Number of Findings",
)


# --------------------------------------------------
# RISK LEVEL FILTER
# --------------------------------------------------

st.subheader("🔎 Filter Security Findings")

risk_filter = st.selectbox(
    "Choose a risk level",
    ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
    key="sample_risk_filter",
)

if risk_filter == "All":
    filtered_findings = findings
else:
    filtered_findings = [
        item for item in findings
        if item.get("risk_level") == risk_filter
    ]

st.caption(
    f"Showing {len(filtered_findings)} of {len(findings)} findings."
)

display_findings_table(
    filtered_findings,
    key_prefix="sample_findings",
)

related_findings_section(
    filtered_findings,
    title="Related Sample Findings",
)

display_finding_explanations(
    filtered_findings,
    title="Sample Security Decisions",
    key_prefix="sample",
)


# --------------------------------------------------
# SIMULATED REMEDIATION
# --------------------------------------------------

st.divider()
st.header("🔧 Simulated Security Remediation")

remediation = workflow["remediation_result"]

st.write("**Remediation status:**", remediation.get("status", "Unknown"))

if remediation.get("verification_passed"):
    st.success(remediation.get("verification_message", "Verification passed."))
else:
    st.warning(remediation.get("verification_message", "Verification requires review."))

col1, col2 = st.columns(2)

with col1:
    st.write("**Before remediation**")
    st.json(remediation.get("original_config", {}))

with col2:
    st.write("**After simulated remediation**")

    after_config = {
        key: value
        for key, value in remediation.items()
        if key not in [
            "original_config",
            "changes",
            "verification_passed",
            "verification_message",
        ]
    }

    st.json(after_config)

st.write("**Recorded changes**")

changes = remediation.get("changes", [])

if changes:
    st.dataframe(
        pd.DataFrame(changes),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No configuration changes were required.")


# --------------------------------------------------
# SECURITY REPORT DOWNLOAD
# --------------------------------------------------

st.divider()
st.header("📄 CloudSentinel Security Report")

report = workflow.get("report", {})

# Overall security summary
summary = report.get("security_summary", {})

st.subheader("Security Assessment Overview")

status = summary.get("overall_status", "Not available")
total = report.get("total_findings", 0)

col1, col2, col3 = st.columns(3)

col1.metric("Overall Security Status", status)
col2.metric("Total Findings", total)
col3.metric(
    "Remediation Verified",
    "Yes" if workflow.get("verification_passed") else "No"
)

# Risk distribution
st.subheader("Risk Distribution")

distribution = summary.get("risk_distribution", {})

risk_df = pd.DataFrame({
    "Risk Level": list(distribution.keys()),
    "Findings": list(distribution.values()),
}).set_index("Risk Level")

st.bar_chart(risk_df)

# Remediation verification
st.subheader("Remediation Verification")

if workflow.get("verification_passed"):
    st.success(workflow.get("verification_message"))
else:
    st.warning(workflow.get("verification_message"))

# Detailed findings
st.subheader("Prioritised Security Findings")

report_findings = report.get(
    "finding_details",
    report.get("findings", [])
)

if report_findings:
    st.dataframe(
        pd.DataFrame(report_findings),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No findings available.")

# Remediation information
st.subheader("Remediation Details")

st.json(report.get("remediation", {}))

# Report preview
st.subheader("Complete Report Preview")

st.json(report)

# Download options
st.subheader("Download Your Reports")

report_text = json.dumps(
    report,
    indent=4,
    default=str,
)

st.download_button(
    label="Download Security Report",
    data=report_text,
    file_name="cloudsentinel_security_report.txt",
    mime="text/plain",
)

st.download_button(
    label="Download JSON Report",
    data=json.dumps(
        report,
        indent=4,
        default=str,
    ),
    file_name="cloudsentinel_security_report.json",
    mime="application/json",
)

# --------------------------------------------------
# TERRAFORM SECURITY SCANNER
# --------------------------------------------------

st.divider()
st.header("📂 Terraform Security Scanner")

st.write(
    "Upload a Terraform `.tf` file to check for selected "
    "cloud security configuration risks."
)

uploaded_file = st.file_uploader(
    "Upload Terraform file",
    type=["tf"],
)

if uploaded_file is not None:

    st.write("**Uploaded file:**", uploaded_file.name)

    if st.button("Scan Terraform File"):

        try:
            with tempfile.TemporaryDirectory() as temp_dir:

                temp_file_path = Path(temp_dir) / uploaded_file.name

                temp_file_path.write_bytes(
                    uploaded_file.getvalue()
                )

                terraform_findings = scan_terraform_file(
                    str(temp_file_path)
                )

            for finding in terraform_findings:
                finding["resource"] = uploaded_file.name

            prioritised_terraform_findings = prioritise_findings(
                terraform_findings
            )

            st.session_state["terraform_findings"] = (
                prioritised_terraform_findings
            )

            st.session_state["terraform_filename"] = uploaded_file.name

        except Exception as error:
            st.error(f"Scanning failed: {error}")


# --------------------------------------------------
# TERRAFORM SCAN RESULTS
# --------------------------------------------------

if "terraform_findings" in st.session_state:

    terraform_results = st.session_state["terraform_findings"]
    
    st.info("YOUR SCAN RESULTS — These findings come from the Terraform file you uploaded and scanned.")    

    st.subheader("📊 Terraform Scan Results")

    st.write(
        f"File scanned: {st.session_state.get('terraform_filename', 'Unknown')}"
    )

    if terraform_results:

        st.success(
            f"Scan completed. Found {len(terraform_results)} security finding(s)."
        )

        # Terraform risk filter
        terraform_risk_filter = st.selectbox(
            "Filter Terraform findings by risk level",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="terraform_risk_filter",
        )

        if terraform_risk_filter == "All":
            filtered_terraform_findings = terraform_results
        else:
            filtered_terraform_findings = [
                item for item in terraform_results
                if item.get("risk_level") == terraform_risk_filter
            ]

        st.caption(
            f"Showing {len(filtered_terraform_findings)} "
            f"of {len(terraform_results)} Terraform findings."
        )

        display_findings_table(
            filtered_terraform_findings,
            key_prefix="terraform_findings",
        )

        related_findings_section(
            filtered_terraform_findings,
            title="Related Terraform Findings",
        )

        display_finding_explanations(
            filtered_terraform_findings,
            title="Terraform Security Decisions",
            key_prefix="terraform",
        )

        # CSV download
        csv_data = pd.DataFrame(terraform_results).to_csv(index=False)

        st.download_button(
            label="Download Terraform Findings CSV",
            data=csv_data,
            file_name="cloudsentinel_terraform_findings.csv",
            mime="text/csv",
        )

        # JSON download
        terraform_json = json.dumps(
            terraform_results,
            indent=4,
            default=str,
        )

        st.download_button(
            label="Download Terraform Findings JSON",
            data=terraform_json,
            file_name="cloudsentinel_terraform_findings.json",
            mime="application/json",
        )

    else:
        st.success(
            "No security findings detected by the current scanner checks."
        )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "CloudSentinel | Explainable Security Prioritisation | "
    "Local-only simulation | No real cloud resources modified"
)