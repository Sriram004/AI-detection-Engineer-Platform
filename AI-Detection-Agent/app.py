from pathlib import Path

import streamlit as st

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from src.analyzer import analyze_alert, load_alert, load_sample_alerts
from src.database import init_db, list_incidents, save_incident
from src.report_generator import export_report


ROOT = Path(__file__).resolve().parent
if load_dotenv:
    load_dotenv(ROOT / ".env")
init_db()

st.set_page_config(page_title="AI Detection Engineer Agent", layout="wide")
st.title("AI Detection Engineer Agent")
st.caption("AI-assisted SOC investigation, detection engineering, and analyst validation.")

with st.sidebar:
    st.header("Alert Source")
    samples = load_sample_alerts(ROOT / "data" / "alerts")
    selected = st.selectbox("Choose alert", ["Upload JSON"] + list(samples.keys()))
    uploaded = st.file_uploader("Upload alert JSON", type=["json"])
    use_openai = st.toggle("Use OpenAI enrichment", value=False)
    st.divider()
    st.caption("Generated rules should be tested before deployment.")

alert = None
if selected != "Upload JSON":
    alert = samples[selected]
elif uploaded is not None:
    alert = load_alert(uploaded)

if alert is None:
    st.info("Choose a sample alert or upload a JSON alert to begin.")
    st.stop()

left, right = st.columns([1, 2])
with left:
    st.subheader("Alert")
    st.json(alert)
with right:
    st.subheader("Investigation Workflow")
    st.write("Analyze the alert, review generated detection content, validate the result, then export the report.")
    analyze_clicked = st.button("Analyze Alert", type="primary", use_container_width=True)

if "analysis" not in st.session_state or analyze_clicked:
    with st.spinner("Analyzing alert and building detection content..."):
        st.session_state.analysis = analyze_alert(alert, use_openai=use_openai)

analysis = st.session_state.analysis
summary_tab, mitre_tab, rules_tab, validation_tab, history_tab = st.tabs(
    ["Summary", "MITRE", "Rules", "Validation", "History"]
)

with summary_tab:
    st.subheader("Investigation Summary")
    st.write(analysis["investigation_summary"])
    st.subheader("Attack Hypothesis")
    st.write(analysis["attack_hypothesis"])
    col1, col2 = st.columns(2)
    col1.metric("Threat Level", analysis["severity"])
    col2.metric("Confidence", f'{analysis["confidence"]}%')
    st.subheader("Response Steps")
    for step in analysis["response_steps"]:
        st.write(f"- {step}")
    st.subheader("False Positive Considerations")
    for item in analysis["false_positive_considerations"]:
        st.write(f"- {item}")
    if analysis.get("openai_enrichment"):
        st.subheader("OpenAI Enrichment")
        st.write(analysis["openai_enrichment"])

with mitre_tab:
    mapping = analysis["mitre_mapping"]
    st.subheader("MITRE ATT&CK Mapping")
    st.write(f'**Tactic:** {mapping["tactic"]}')
    st.write(f'**Technique:** {mapping["technique_id"]} - {mapping["technique_name"]}')
    st.write(f'**Rationale:** {mapping["rationale"]}')
    st.link_button("Open MITRE Reference", mapping["reference"])

with rules_tab:
    sigma_col, kql_col = st.columns(2)
    with sigma_col:
        st.subheader("Sigma Rule")
        st.code(analysis["sigma_rule"], language="yaml")
    with kql_col:
        st.subheader("Microsoft Sentinel KQL")
        st.code(analysis["kql_rule"], language="kusto")

with validation_tab:
    st.subheader("Analyst Validation")
    mitre_ok = st.checkbox("MITRE technique is correct")
    logic_ok = st.checkbox("Detection logic matches the alert")
    fp_ok = st.checkbox("False positives reviewed")
    response_ok = st.checkbox("Response steps are appropriate")
    status = st.selectbox("Decision", ["Needs Review", "Approved", "Rejected"])
    analyst = st.text_input("Analyst", value="SOC Analyst")
    notes = st.text_area("Analyst notes", height=120)

    if st.button("Save Validation And Export", type="primary"):
        validation = {
            "mitre_ok": mitre_ok,
            "logic_ok": logic_ok,
            "false_positives_ok": fp_ok,
            "response_ok": response_ok,
            "status": status,
            "analyst": analyst,
            "notes": notes,
        }
        incident_id = save_incident(alert, analysis, validation)
        report_path = export_report(ROOT, incident_id, alert, analysis, validation)
        st.success(f"Incident {incident_id} saved. Report exported to {report_path}.")

with history_tab:
    st.subheader("Incident History")
    incidents = list_incidents()
    if incidents:
        st.dataframe(incidents, use_container_width=True, hide_index=True)
    else:
        st.write("No saved incidents yet.")
