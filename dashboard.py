import streamlit as st
import pandas as pd
import plotly.express as px
import os
from Backend.database import fetch_all_logs, get_db_connection
from Backend.ai_suite import scan_pdf_file_pure_ai, analyze_email_pure_ai
from Backend.gemini_engine import deep_scan_with_gemini

st.set_page_config(page_title="AlphaShield AI SOC Console", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    .stApp { background-color: #0b0f19; color: #f3f4f6; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AlphaShield AI Enterprise Security Console")
st.caption("Multi-Engine AI Threat Detection & Telemetry Platform")

# Ensure database tables exist before querying logs
get_db_connection()

# Sidebar Key Config
with st.sidebar:
    st.header("⚙️ System Config")
    api_key_input = st.text_input("Gemini API Key:", type="password")
    if api_key_input:
        os.environ["GEMINI_API_KEY"] = api_key_input
        st.success("API Key Active!")

menu = st.sidebar.radio("Navigation", [
    "SOC Overview Dashboard", 
    "PDF ML Payload Scanner", 
    "Deep Email NLP Inspector", 
    "Gemini 2.0 Multimodal Scanner",
    "Threat Logs Audit"
])

if menu == "SOC Overview Dashboard":
    st.subheader("📊 Pure AI Model Telemetry")
    logs = fetch_all_logs()
    if logs:
        df = pd.DataFrame(logs, columns=["ID", "Timestamp", "Scan Type", "Target", "Risk Score", "Is Threat", "Engine", "Details"])
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Scans Executed", len(df))
        c2.metric("AI Blocked Threats", len(df[df["Is Threat"] == 1]))
        c3.metric("Verified Safe Assets", len(df[df["Is Threat"] == 0]))
        c4.metric("Average Model Confidence", f"{df['Risk Score'].mean():.1f}%")
        
        st.write("---")
        fig = px.histogram(df, x="Risk Score", nbins=10, title="Neural & ML Risk Score Probability Distribution", color_discrete_sequence=["#06b6d4"])
        st.plotly_chart(fig, use_container_width=True)

elif menu == "PDF ML Payload Scanner":
    st.subheader("📄 RandomForest Structural PDF Analyzer")
    uploaded_file = st.file_uploader("Upload PDF Document:", type=["pdf"])
    
    if uploaded_file is not None and st.button("Execute Pure ML Scan"):
        with st.spinner("Extracting Vector Features & Running Model Inference..."):
            res = scan_pdf_file_pure_ai(uploaded_file.read(), uploaded_file.name)
            if res["is_threat"]:
                st.error(f"🚨 MALICIOUS PDF DETECTED - ML Score: {res['risk_score']}%")
            else:
                st.success(f"✅ CLEAN DOCUMENT - ML Score: {res['risk_score']}%")
            st.json(res)

elif menu == "Deep Email NLP Inspector":
    st.subheader("✉️ DistilBERT Neural Intent Analysis")
    email_text = st.text_area("Input Email Text:", height=150)
    
    if st.button("Run Transformer Model Inference"):
        if email_text:
            with st.spinner("Calculating Neural Softmax Probabilities..."):
                res = analyze_email_pure_ai(email_text)
                if res["is_threat"]:
                    st.error(f"🚨 SPEAR-PHISHING THREAT: Neural Risk Score {res['risk_score']}%")
                else:
                    st.success(f"✅ LEGITIMATE TEXT: Neural Risk Score {res['risk_score']}%")
                st.json(res)

elif menu == "Gemini 2.0 Multimodal Scanner":
    st.subheader("🤖 Gemini 2.0 Deep Semantic Engine")
    target_name = st.text_input("Target URL or Asset Name:", placeholder="https://suspicious-site.com")
    raw_content = st.text_area("Webpage HTML / DOM Snippet / Raw Script:", height=200)

    if st.button("Run Gemini Deep Analysis"):
        if raw_content and target_name:
            with st.spinner("Gemini 2.0 Reasoning in Progress..."):
                res = deep_scan_with_gemini("Webpage DOM", raw_content, target_name)
                if res["gemini_active"]:
                    if res["is_threat"]:
                        st.error(f"🚨 GEMINI ALERT ({res['attack_vector']}): Risk Score {res['risk_score']}%")
                    else:
                        st.success(f"✅ Safe Context: Risk Score {res['risk_score']}%")
                    st.write("**Reasoning:**", res["ai_reasoning"])
                else:
                    st.warning(res["reasoning"])

elif menu == "Threat Logs Audit":
    st.subheader("📜 AI Model Inference Audit Trail")
    logs = fetch_all_logs()
    if logs:
        df = pd.DataFrame(logs, columns=["ID", "Timestamp", "Scan Type", "Target", "Risk Score", "Is Threat", "Engine", "Details"])
        st.dataframe(df, use_container_width=True)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Export Telemetry Log CSV", csv, "alphashield_audit.csv", "text/csv")