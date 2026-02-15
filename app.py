import streamlit as st
import os
import pandas as pd
import plotly.express as px
from analyzer import analyze_apk
from report_generator import generate_report

# --- 1. PAGE CONFIGURATION & INITIALIZATION ---
st.set_page_config(
    page_title="APK Sentinel | Mobile SecOps",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State (The "Memory" fix for downloads)
if 'scan_completed' not in st.session_state:
    st.session_state.scan_completed = False
    st.session_state.findings = []
    st.session_state.metadata = {}
    st.session_state.current_file = None

# --- 2. CUSTOM CSS FOR PREMIUM UI ---
st.markdown("""
<style>
    /* Glowing effect for the main title */
    .glow-title {
        font-size: 3.5rem;
        font-weight: 900;
        background: -webkit-linear-gradient(45deg, #00FF87, #60EFFF);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0rem;
        padding-bottom: 0rem;
    }
    
    /* Subtitle styling */
    .sub-title {
        font-size: 1.2rem;
        color: #A0AEC0;
        margin-bottom: 2rem;
        font-weight: 400;
    }
    
    /* Premium styling for Metric Cards */
    [data-testid="stMetric"] {
        background-color: rgba(26, 32, 44, 0.6);
        border: 1px solid #2D3748;
        border-radius: 12px;
        padding: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    
    /* Style the tabs to look more like modern buttons */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: rgba(26, 32, 44, 0.4);
        border-radius: 6px;
        padding: 10px 20px;
        border: 1px solid #2D3748;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2D3748;
        border-color: #00FF87;
        color: #00FF87 !important;
    }

    /* Premium Export Button Gradients & Hover Animations */
    [data-testid="stDownloadButton"] button {
        background: linear-gradient(90deg, #2b5876 0%, #4e4376 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: 600;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    [data-testid="stDownloadButton"] button:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 15px rgba(43, 88, 118, 0.5);
        color: #00FF87;
        border: none;
    }
</style>
""", unsafe_allow_html=True)

# --- 3. SIDEBAR (UPLOAD & CONTROLS) ---
with st.sidebar:
    # A generic security shield icon for branding
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80) 
    st.markdown("## Control Panel")
    st.markdown("Upload your Android Package (.apk) to initiate the static analysis engine.")
    
    uploaded_file = st.file_uploader("Drop APK Here", type=["apk"])
    
    # Detect if a NEW file was uploaded to reset memory
    if uploaded_file and uploaded_file.name != st.session_state.current_file:
        st.session_state.scan_completed = False
        st.session_state.current_file = uploaded_file.name

    st.markdown("---")
    st.markdown("**Engine Status:**")
    if uploaded_file:
        st.success("🟢 Ready to Scan")
        run_scan = st.button("🚀 INITIATE SCAN", type="primary", use_container_width=True)
    else:
        st.warning("🟡 Waiting for payload")
        run_scan = False

    st.markdown("---")
    st.caption("Developed for Hackathon Pitch")

# --- 4. MAIN DASHBOARD AREA ---
st.markdown('<p class="glow-title">APK Sentinel</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Next-Gen Static Mobile Application Security Testing (SAST)</p>', unsafe_allow_html=True)

if not uploaded_file:
    # Beautiful Landing Page State
    st.info("👈 Please upload an APK file in the sidebar to begin analysis.")
    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### 🔍 Deep Static Analysis")
        st.write("Decompiles DEX files and parses the Android Manifest to detect misconfigurations and hardcoded secrets before production.")
    with col2:
        st.markdown("### 📊 OWASP Mapping")
        st.write("Automatically categorizes discovered vulnerabilities to the OWASP Mobile Top 10 for industry-standard compliance.")
    with col3:
        st.markdown("### 📄 DevSecOps Ready")
        st.write("Generates interactive HTML dashboards, compliance-ready PDFs, and raw JSON artifacts for CI/CD pipelines.")

elif run_scan or st.session_state.scan_completed:
    
    # Only run the heavy analysis if the button was JUST clicked
    if run_scan:
        temp_path = uploaded_file.name
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with st.status("🕵️‍♂️ **Analyzing APK Payload...**", expanded=True) as status:
            st.write("1️⃣ Extracting APK manifest and DEX files...")
            st.write("2️⃣ Running pattern matching for secrets and cloud endpoints...")
            
            # Save the results to session memory
            findings, metadata = analyze_apk(temp_path)
            st.session_state.findings = findings
            st.session_state.metadata = metadata
            
            st.write("3️⃣ Scoring risk and generating compliance reports...")
            generate_report(findings, metadata)
            
            # Lock in the completion state
            st.session_state.scan_completed = True
            status.update(label="✅ Analysis Complete!", state="complete", expanded=False)

    # Use the memory variables to populate the dashboard
    findings = st.session_state.findings
    metadata = st.session_state.metadata

    if not findings:
        st.balloons()
        st.success("🎉 Incredible! Zero vulnerabilities detected. Your app is locked down.")
    else:
        df = pd.DataFrame(findings)

        # Tabs for UI organization
        tab1, tab2, tab3 = st.tabs(["📊 Executive Dashboard", "🚨 Technical Findings", "📦 App Metadata"])

        # --- TAB 1: EXECUTIVE DASHBOARD ---
        with tab1:
            st.markdown("### Threat Intelligence Summary")
            
            m1, m2, m3, m4 = st.columns(4)
            critical = len(df[df['severity'] == 'Critical'])
            high = len(df[df['severity'] == 'High'])
            medium = len(df[df['severity'] == 'Medium'])
            low = len(df[df['severity'] == 'Low'])
            
            m1.metric("🔴 Critical Risk", critical, delta="Immediate Action Required" if critical > 0 else "Clear", delta_color="inverse")
            m2.metric("🟠 High Risk", high)
            m3.metric("🟡 Medium Risk", medium)
            m4.metric("🟢 Low Risk", low)

            st.markdown("---")

            c1, c2 = st.columns(2)
            
            with c1:
                severity_counts = df['severity'].value_counts().reset_index()
                severity_counts.columns = ['Severity', 'Count']
                color_map = {"Critical": "#FF4B4B", "High": "#FFA421", "Medium": "#FFE312", "Low": "#00CC96"}
                
                fig_pie = px.pie(severity_counts, values='Count', names='Severity', 
                                 title="Vulnerability Distribution",
                                 color='Severity', color_discrete_map=color_map, hole=0.5)
                fig_pie.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)") 
                st.plotly_chart(fig_pie, use_container_width=True)

            with c2:
                owasp_counts = df['owasp'].value_counts().reset_index()
                owasp_counts.columns = ['OWASP Category', 'Count']
                
                fig_bar = px.bar(owasp_counts, x='Count', y='OWASP Category', orientation='h',
                                 title="OWASP Mobile Top 10 Mapping",
                                 color='Count', color_continuous_scale='Reds')
                fig_bar.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", 
                                      yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(fig_bar, use_container_width=True)

            # Premium Download Section
            st.markdown("### 📥 DevSecOps Export Artifacts")
            d1, d2, d3 = st.columns(3)
            
            if os.path.exists("report.html"):
                with open("report.html", "rb") as file:
                    d1.download_button("🌐 Download HTML Report", data=file.read(), file_name="Sentinel_Report.html", mime="text/html", use_container_width=True)
            if os.path.exists("report.pdf"):
                with open("report.pdf", "rb") as file:
                    d2.download_button("📄 Download PDF Report", data=file.read(), file_name="Sentinel_Report.pdf", mime="application/pdf", use_container_width=True)
            if os.path.exists("report.json"):
                with open("report.json", "rb") as file:
                    d3.download_button("👨‍💻 Download JSON API", data=file.read(), file_name="Sentinel_Report.json", mime="application/json", use_container_width=True)

        # --- TAB 2: TECHNICAL FINDINGS ---
        with tab2:
            st.markdown("### Vulnerability Drill-Down")
            
            # Interactive Filter 
            filter_sev = st.multiselect("Filter by Severity:", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
            filtered_df = df[df['severity'].isin(filter_sev)]
            
            if filtered_df.empty:
                st.info("No vulnerabilities match the selected filters.")
            
            for idx, row in filtered_df.iterrows():
                emoji = "🔴" if row['severity'] == "Critical" else "🟠" if row['severity'] == "High" else "🟡" if row['severity'] == "Medium" else "🟢"
                with st.expander(f"{emoji} [{row['severity']}] {row['title']}"):
                    st.markdown(f"**OWASP Category:** `{row['owasp']}`")
                    st.markdown(f"**Description:** {row['description']}")
                    st.warning(f"**Remediation:** {row['remediation']}")

        # --- TAB 3: APP METADATA ---
        with tab3:
            st.markdown("### Extracted Application Data")
            st.json(metadata)