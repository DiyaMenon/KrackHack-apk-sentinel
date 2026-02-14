# APK Sentinel

**APK Sentinel** is a static mobile application security analyzer that performs automated vulnerability detection on Android APK files.

It analyzes APKs using static analysis techniques and generates:

- Interactive HTML Security Report  
- PDF Report  
- JSON Report  
- Risk Score & Security Grade  
- OWASP Mobile Top 10 Categorization  

---

## Features

### Static Analysis Engine
- Dangerous permission detection
- Exported components analysis
- Hardcoded secrets detection
- Weak cryptography detection (MD5, SHA1, DES)
- Hardcoded HTTP endpoints
- Raw IP address detection
- WebView misconfiguration detection
- Firebase & AWS endpoint detection
- Certificate metadata extraction

---

### Smart Risk Scoring
- Weighted severity scoring
- Overall Risk Level (Low / Medium / High)
- Security Grade (A–F)
- Risk Justification Engine

---

### Report Generation
- Interactive collapsible findings
- Search functionality
- Color-coded severity
- Downloadable:
  - HTML report
  - PDF report
  - JSON report

---

## Tech Stack

- Python
- Androguard
- Streamlit
- ReportLab
- HTML / CSS / JavaScript

---

## How To Run Locally

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/KrackHack-apk-sentinel.git
cd KrackHack-apk-sentinel

### Set up Virtual Environment
python -m venv venv
venv\Scripts\activate   # Windows

### Install Requirements
pip install -r requirements.txt

### Run Streamlit App
streamlit run app.py

### App Runs at
http://localhost:8501
```

## The final OUTPUT

![Streamlit](images/APK Sentinel.png)

![HTML Pages](images/HTML1.png)

![HTML Pages](images/HTML2.png)

![HTML Pages](images/HTML3.png)



