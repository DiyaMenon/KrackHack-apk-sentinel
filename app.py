import streamlit as st
import os
import webbrowser
from analyzer import analyze_apk
from report_generator import generate_report

st.set_page_config(page_title="APK Sentinel", page_icon="🔐")

st.title("🔐 APK Sentinel")
st.subheader("Static Mobile App Security Analyzer")

uploaded_file = st.file_uploader("Upload APK", type=["apk"])

if uploaded_file:
    temp_path = uploaded_file.name

    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    if st.button("Analyze"):
        findings, metadata = analyze_apk(temp_path)

        generate_report(findings, metadata)

        st.success(f"{len(findings)} issues found!")

        # ✅ Open HTML report automatically
        report_path = os.path.abspath("report.html")
        webbrowser.open(f"file://{report_path}")

    # Optional cleanup
    # os.remove(temp_path)