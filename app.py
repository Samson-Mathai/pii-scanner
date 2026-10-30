"""KenyaShield: PII Scanner & Risk Analyzer for Kenya Data Protection Act 2019.

Zero try-except blocks used.
"""

import os
import io
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from scanner.detector import PIIDetector
from scanner.classifier import PIIClassifier
from scanner.redactor import PIIRedactor
from scanner.readers import DocumentReader

st.set_page_config(
    page_title="KenyaShield | PII & KDPA Risk Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize scanner singletons in session state
if "detector" not in st.session_state:
    st.session_state["detector"] = PIIDetector()
if "classifier" not in st.session_state:
    st.session_state["classifier"] = PIIClassifier()
if "redactor" not in st.session_state:
    st.session_state["redactor"] = PIIRedactor()

detector = st.session_state["detector"]
classifier = st.session_state["classifier"]
redactor = st.session_state["redactor"]

# Sidebar configuration
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=72)
st.sidebar.title("KenyaShield")
st.sidebar.caption("Data Protection Act 2019 Analyzer")
st.sidebar.markdown("---")

app_mode = st.sidebar.radio(
    "Navigation Mode",
    ["📁 Scan Files", "🧪 Synthetic Benchmark Suite", "📜 KDPA Legal & Design Guide"],
)

st.sidebar.markdown("---")
st.sidebar.info(
    "**KDPA Compliance Scope**\n"
    "- Direct Identifiers (Phone, National ID, KRA PIN, Bank A/C)\n"
    "- Transaction IDs (M-Pesa 10-char codes)\n"
    "- Sensitive Personal Data (Health, Biometrics, Salary)\n"
    "- Natural Language NER (Names, Locations)"
)

# -------------------------------------------------------------
# MODE 1: FILE SCANNER
# -------------------------------------------------------------
if app_mode == "📁 Scan Files":
    st.title("🛡️ KenyaShield: PII Scanner & Risk Assessor")
    st.markdown(
        "Automated detection of Kenyan personal and sensitive personal data across "
        "`.txt`, `.csv`, `.pdf`, and `.docx` documents."
    )

    uploaded_files = st.file_uploader(
        "Upload document(s) for compliance scan",
        type=["txt", "csv", "pdf", "docx"],
        accept_multiple_files=True,
    )

    scan_targets = []
    if uploaded_files:
        scan_targets = uploaded_files

    if not scan_targets:
        st.info("👆 Please upload one or more files to start scanning, or switch to the **Synthetic Benchmark Suite** in the sidebar.")
    else:
        all_results = []
        file_risk_summaries = []

        with st.spinner("Analyzing document contents against Kenya Data Protection Act rules..."):
            for f_item in scan_targets:
                read_res = DocumentReader.read_file(f_item)
                fname = read_res.get("filename", "unknown")
                text = read_res.get("text", "")
                ftype = read_res.get("file_type", "UNKNOWN")

                raw_findings = detector.scan(text)
                classified_findings = classifier.classify_all(raw_findings)
                risk_summary = classifier.compute_file_risk(classified_findings)

                for f in classified_findings:
                    f["filename"] = fname
                    f["file_type"] = ftype
                    all_results.append(f)

                file_risk_summaries.append({
                    "filename": fname,
                    "file_type": ftype,
                    "total_findings": risk_summary["total_findings"],
                    "personal_data_count": risk_summary["personal_data_count"],
                    "sensitive_data_count": risk_summary["sensitive_data_count"],
                    "risk_score": risk_summary["risk_score"],
                    "risk_level": risk_summary["risk_level"],
                    "raw_text": text,
                    "findings": classified_findings,
                })

        # Summary KPIs
        st.markdown("### 📊 Executive Compliance Overview")
        col1, col2, col3, col4 = st.columns(4)

        total_findings_count = len(all_results)
        total_sensitive_count = sum(1 for f in all_results if f.get("category") == "Sensitive Personal Data")
        max_risk = max((f["risk_score"] for f in file_risk_summaries), default=0)

        col1.metric("Scanned Files", len(file_risk_summaries))
        col2.metric("Total PII Findings", total_findings_count)
        col3.metric("Sensitive Personal Findings", total_sensitive_count, delta="Section 44 Alert" if total_sensitive_count > 0 else None)
        col4.metric("Highest File Risk Score", f"{max_risk}/100")

        # Interactive Charts
        if file_risk_summaries:
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("File Risk Scores & Classification Level")
                df_files = pd.DataFrame([
                    {
                        "File": r["filename"],
                        "Risk Score": r["risk_score"],
                        "Risk Level": r["risk_level"],
                        "Sensitive Findings": r["sensitive_data_count"],
                    }
                    for r in file_risk_summaries
                ])
                fig_risk = px.bar(
                    df_files,
                    x="File",
                    y="Risk Score",
                    color="Risk Level",
                    color_discrete_map={
                        "Low": "#28a745",
                        "Medium": "#ffc107",
                        "High": "#fd7e14",
                        "Critical": "#dc3545",
                    },
                    text="Risk Score",
                    range_y=[0, 105],
                )
                fig_risk.update_layout(xaxis_tickangle=-30)
                st.plotly_chart(fig_risk, use_container_width=True)

            with c2:
                st.subheader("Findings by Data Category")
                if all_results:
                    cat_counts = pd.Series([f["category"] for f in all_results]).value_counts().reset_index()
                    cat_counts.columns = ["Category", "Count"]
                    fig_cat = px.pie(
                        cat_counts,
                        names="Category",
                        values="Count",
                        hole=0.45,
                        color="Category",
                        color_discrete_map={
                            "Personal Data": "#0d6efd",
                            "Sensitive Personal Data": "#dc3545",
                        },
                    )
                    st.plotly_chart(fig_cat, use_container_width=True)

            # Chart 2: Findings by specific type
            st.subheader("Distribution of Detected Identifiers")
            if all_results:
                type_counts = pd.Series([f["finding_type"] for f in all_results]).value_counts().reset_index()
                type_counts.columns = ["Identifier Type", "Count"]
                fig_types = px.bar(
                    type_counts,
                    x="Identifier Type",
                    y="Count",
                    color="Identifier Type",
                    text="Count",
                )
                st.plotly_chart(fig_types, use_container_width=True)

        # Findings Detail Table
        st.markdown("### 📋 Detailed Inspection Register")
        if all_results:
            df_findings = pd.DataFrame(all_results)

            # Filters
            fcol1, fcol2, fcol3 = st.columns(3)
            with fcol1:
                selected_files = st.multiselect(
                    "Filter by Document",
                    options=list(df_findings["filename"].unique()),
                    default=list(df_findings["filename"].unique()),
                )
            with fcol2:
                selected_cats = st.multiselect(
                    "Filter by Category",
                    options=list(df_findings["category"].unique()),
                    default=list(df_findings["category"].unique()),
                )
            with fcol3:
                selected_sevs = st.multiselect(
                    "Filter by Severity",
                    options=list(df_findings["severity"].unique()),
                    default=list(df_findings["severity"].unique()),
                )

            filtered_df = df_findings[
                df_findings["filename"].isin(selected_files)
                & df_findings["category"].isin(selected_cats)
                & df_findings["severity"].isin(selected_sevs)
            ]

            display_cols = [
                "filename", "line_number", "finding_type", "value",
                "category", "severity", "context", "legal_basis"
            ]
            st.dataframe(
                filtered_df[display_cols],
                use_container_width=True,
                height=320,
            )

            # CSV Download Report
            csv_buffer = io.StringIO()
            filtered_df[display_cols].to_csv(csv_buffer, index=False)
            st.download_button(
                label="📥 Download Compliance Report (CSV)",
                data=csv_buffer.getvalue(),
                file_name="kenyashield_compliance_findings.csv",
                mime="text/csv",
            )
        else:
            st.success("✅ Clean Scan: No Kenyan PII or Sensitive Personal Data detected in the uploaded file(s).")

        # Non-destructive Redaction Panel
        st.markdown("---")
        st.markdown("### 🛡️ Non-Destructive Data Redaction Engine")
        st.caption(
            "Safely transform documents to eliminate PII risk. "
            "Original files are never modified or overwritten."
        )

        redact_target_name = st.selectbox(
            "Select file to redact:",
            options=[r["filename"] for r in file_risk_summaries],
        )

        selected_file_summary = None
        for item in file_risk_summaries:
            if item["filename"] == redact_target_name:
                selected_file_summary = item
                break

        if selected_file_summary:
            rcol1, rcol2 = st.columns([1, 2])
            with rcol1:
                redaction_mode = st.radio(
                    "Redaction Technique:",
                    [
                        ("mask", "Masking (e.g. 07******45, ******10, A*********Z)"),
                        ("redact", "Full Redaction (e.g. [REDACTED_PHONE_NUMBER])"),
                        ("hash", "One-Way Cryptographic Hashing (SHA-256)"),
                    ],
                    format_func=lambda x: x[1],
                )[0]

                save_disk = st.button("💾 Save Redacted Copy to Disk")

            with rcol2:
                original_text = selected_file_summary["raw_text"]
                target_findings = selected_file_summary["findings"]
                redacted_output = redactor.redact_text(original_text, target_findings, method=redaction_mode)

                tab_redact, tab_orig = st.tabs(["🔒 Redacted Preview", "📄 Original Preview"])
                with tab_redact:
                    st.text_area("Redacted Output", redacted_output, height=220)
                with tab_orig:
                    st.text_area("Original Content", original_text, height=220)

                st.download_button(
                    label="📥 Download Redacted Document",
                    data=redacted_output,
                    file_name=f"redacted_{redact_target_name}.txt",
                    mime="text/plain",
                )

                if save_disk:
                    saved_path = redactor.save_redacted_copy(
                        redact_target_name, redacted_output, output_dir="data/redacted"
                    )
                    st.success(f"✅ Successfully written to separate directory: `{saved_path}`")

# -------------------------------------------------------------
# MODE 2: SYNTHETIC BENCHMARK SUITE
# -------------------------------------------------------------
elif app_mode == "🧪 Synthetic Benchmark Suite":
    st.title("🧪 Synthetic Benchmark & False-Positive Verification")
    st.markdown(
        "> [!NOTE]\n"
        "> **SYNTHETIC DATA ONLY**: All datasets below are procedurally generated by Faker "
        "and contain exclusively fictional records. None represent actual Kenyan citizens or organizations."
    )

    synthetic_dir = os.path.join("data", "synthetic")
    if not os.path.exists(synthetic_dir):
        st.warning("Synthetic test data folder not found. Click below to generate it.")
        if st.button("Generate Synthetic Benchmark Datasets"):
            from generate_data import generate_all_synthetic_data
            generate_all_synthetic_data()
            st.rerun()
    else:
        test_files = sorted(os.listdir(synthetic_dir))
        selected_synthetic = st.selectbox("Select a synthetic benchmark file to evaluate:", test_files)

        if selected_synthetic:
            full_path = os.path.join(synthetic_dir, selected_synthetic)
            res = DocumentReader.read_file(full_path)
            raw_text = res.get("text", "")

            st.write(f"**Format**: `{res.get('file_type')}` | **File Path**: `{full_path}`")

            # Execute scan
            findings = detector.scan(raw_text)
            classified = classifier.classify_all(findings)
            risk = classifier.compute_file_risk(classified)

            bcol1, bcol2, bcol3, bcol4 = st.columns(4)
            bcol1.metric("Findings Detected", len(classified))
            bcol2.metric("Personal Identifiers", risk["personal_data_count"])
            bcol3.metric("Sensitive Categories", risk["sensitive_data_count"])
            bcol4.metric("Risk Score", f"{risk['risk_score']}/100 ({risk['risk_level']})")

            if selected_synthetic == "false_positive_control.txt":
                st.info(
                    "**False-Positive Control Test**: This file contains 8-digit SKU and batch codes without "
                    "statutory identification keywords. Notice that the detector correctly ignores them!"
                )
                if len(classified) == 0:
                    st.success("🎯 **VERIFIED**: Zero false positives detected! 8-digit numbers without ID context were correctly rejected.")
                else:
                    st.warning(f"Detected {len(classified)} items in control file.")

            tab_table, tab_content = st.tabs(["📋 Classified Findings", "📄 Raw Content"])
            with tab_table:
                if classified:
                    df_s = pd.DataFrame(classified)[
                        ["finding_type", "value", "category", "severity", "line_number", "context"]
                    ]
                    st.dataframe(df_s, use_container_width=True)
                else:
                    st.write("No PII detected in this benchmark document.")
            with tab_content:
                st.text_area("File Content", raw_text, height=260)

# -------------------------------------------------------------
# MODE 3: KDPA LEGAL & DESIGN GUIDE
# -------------------------------------------------------------
else:
    st.title("📜 Kenya Data Protection Act 2019: System Architecture")
    st.markdown(
        """
        ### 1. Legal Alignment: Sections & Principles
        KenyaShield maps directly to the statutory requirements of the **Data Protection Act No. 24 of 2019**:

        | Section | Statutory Provision | KenyaShield Technical Implementation |
        | :--- | :--- | :--- |
        | **Section 2** | Definition of Personal Data | Identifies direct and indirect identifiers: Phone (+254/07xx), National IDs, KRA Tax PINs, Emails, M-Pesa codes, Bank Accounts. |
        | **Section 44** | Processing of Sensitive Personal Data | Flags health data (diagnosis, HIV, prescription), biometric data (fingerprint, retina), and financial remuneration (salary, payslip). |
        | **Section 25(b)** | Data Minimization Principle | Offers instant masking and redaction to reduce unnecessary personal data exposure across reports. |
        | **Section 25(c)** | Purpose Limitation | Categorizes findings by data type to verify if collected elements match declared processing purposes. |
        | **Section 41** | Security of Personal Data | Provides cryptographic SHA-256 pseudonymization and saves redacted outputs to isolated directories. |

        ### 2. False-Positive Mitigation Engineering
        - **National ID numbers (7–8 digits)**: Kenya National IDs share character lengths with warehouse SKUs, product barcodes, order IDs, and dates. KenyaShield enforces context proximity: 7–8 digit numbers are only classified as National IDs when situated near keywords like `ID`, `National ID`, `Kitambulisho`, `ID No`.
        - **M-Pesa Transaction Codes (10 alphanumeric)**: Confirmed only within proximity of transactional keywords (`M-Pesa`, `Confirmed`, `Txn`, `Paybill`, `Till`).
        - **Bank Account Numbers (10–14 digits)**: Verified only when adjacent to banking account keywords (`A/C`, `Account Number`, `Bank Acc`).

        ### 3. Technical Caveats & Limitations
        - **Regex vs Dynamic Text**: Regular expressions target known syntactic structures. Malformed or non-standard IDs may produce false negatives.
        - **NER Language Context**: spaCy NER models are trained primarily on standard English corpora. Unusual or localized colloquialisms may require fine-tuning.
        """
    )
