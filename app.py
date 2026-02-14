import streamlit as st
import os
from analyzer import analyze_apk
from report_generator import generate_report

st.set_page_config(page_title="APK Sentinel", page_icon="🔐")

st.title("🔐 APK Sentinel")
st.subheader("Static Mobile App Security Analyzer")

uploaded_file = st.file_uploader("Upload APK", type=["apk"])

if uploaded_file:
    with open(uploaded_file.name, "wb") as f:
        f.write(uploaded_file.getbuffer())

    if st.button("Analyze"):
        findings = analyze_apk(uploaded_file.name)
        generate_report(findings)

        st.success(f"{len(findings)} issues found!")

        with open("report.html", "rb") as file:
            st.download_button(
                label="Download Report",
                data=file,
                file_name="report.html"
            )

    os.remove(uploaded_file.name)