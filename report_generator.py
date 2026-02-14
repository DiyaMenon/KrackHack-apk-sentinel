from datetime import datetime
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter


SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}


# ----------------------------------
# Risk Justification Engine
# ----------------------------------

def generate_risk_justification(total_score, critical_count, high_count):
    if critical_count > 0:
        return "Critical vulnerabilities detected. Immediate remediation required."
    if high_count >= 5:
        return "Multiple high severity issues significantly increase attack surface."
    if total_score > 50:
        return "Accumulated risk score indicates serious security misconfigurations."
    return "Risk level based on detected vulnerabilities and severity distribution."


# ----------------------------------
# PDF Generator
# ----------------------------------

def generate_pdf(findings, metadata, total_score, risk_level):
    doc = SimpleDocTemplate("report.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("APK Sentinel Security Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"Risk Level: {risk_level}", styles["Normal"]))
    elements.append(Paragraph(f"Total Risk Score: {total_score}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Application Metadata", styles["Heading2"]))
    elements.append(Paragraph(f"Package: {metadata['package_name']}", styles["Normal"]))
    elements.append(Paragraph(f"Version: {metadata['version_name']}", styles["Normal"]))
    elements.append(Paragraph(f"Min SDK: {metadata['min_sdk']}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Findings", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    for f in findings:
        elements.append(Paragraph(f"[{f['severity']}] {f['title']}", styles["Normal"]))
        elements.append(Paragraph(f"Description: {f['description']}", styles["Normal"]))
        elements.append(Paragraph(f"Remediation: {f['remediation']}", styles["Normal"]))
        elements.append(Spacer(1, 8))

    doc.build(elements)


# ----------------------------------
# Main Report Generator
# ----------------------------------

def generate_report(findings, metadata, output_file="report.html"):

    total_score = sum(SEVERITY_SCORES.get(f["severity"], 0) for f in findings)

    if total_score > 60:
        risk_level = "High Risk"
        risk_color = "#ef4444"
        risk_bg = "rgba(239, 68, 68, 0.1)"
        accent = "#dc2626"
    elif total_score > 25:
        risk_level = "Medium Risk"
        risk_color = "#f59e0b"
        risk_bg = "rgba(245, 158, 11, 0.1)"
        accent = "#d97706"
    else:
        risk_level = "Low Risk"
        risk_color = "#10b981"
        risk_bg = "rgba(16, 185, 129, 0.1)"
        accent = "#059669"

    critical_count = sum(1 for f in findings if f["severity"] == "Critical")
    high_count = sum(1 for f in findings if f["severity"] == "High")
    medium_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")

    if total_score > 80:
        grade = "F"
    elif total_score > 60:
        grade = "D"
    elif total_score > 40:
        grade = "C"
    elif total_score > 20:
        grade = "B"
    else:
        grade = "A"

    risk_reason = generate_risk_justification(total_score, critical_count, high_count)

    # Generate JSON
    with open("report.json", "w") as f:
        json.dump({
            "metadata": metadata,
            "risk_level": risk_level,
            "total_score": total_score,
            "grade": grade,
            "findings": findings
        }, f, indent=4)

    # Generate PDF
    generate_pdf(findings, metadata, total_score, risk_level)

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Sentinel Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

        :root {{
            --primary: {risk_color};
            --primary-light: {risk_bg};
            --accent: {accent};
            --dark: #0f172a;
            --slate-900: #0f172a;
            --slate-800: #1e293b;
            --slate-700: #334155;
            --slate-600: #475569;
            --slate-400: #94a3b8;
            --slate-200: #e2e8f0;
            --slate-100: #f1f5f9;
            --white: #ffffff;
        }}

        body {{
            font-family: 'Outfit', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1a1f35 100%);
            color: var(--slate-600);
            min-height: 100vh;
            overflow-x: hidden;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}

        /* Header Section */
        .header {{
            margin-bottom: 50px;
            animation: slideDown 0.6s ease-out;
        }}

        .header-top {{
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
        }}

        .logo-icon {{
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, {risk_color} 0%, {accent} 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }}

        .header-text h1 {{
            font-size: 42px;
            font-weight: 700;
            background: linear-gradient(135deg, var(--white) 0%, var(--slate-200) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }}

        .header-text p {{
            color: var(--slate-400);
            font-size: 14px;
            font-weight: 300;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        /* Risk Banner */
        .risk-banner {{
            background: linear-gradient(135deg, {risk_color} 0%, {accent} 100%);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 40px;
            color: white;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            position: relative;
            overflow: hidden;
            animation: slideUp 0.7s ease-out;
        }}

        .risk-banner::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 300px;
            height: 300px;
            background: rgba(255,255,255,0.1);
            border-radius: 50%;
            animation: float 6s ease-in-out infinite;
        }}

        .risk-content {{
            position: relative;
            z-index: 2;
        }}

        .risk-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            opacity: 0.9;
            margin-bottom: 12px;
        }}

        .risk-level {{
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 20px;
            letter-spacing: -1px;
        }}

        .risk-score {{
            display: flex;
            gap: 40px;
            flex-wrap: wrap;
        }}

        .score-item {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .score-number {{
            font-size: 32px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}

        .score-label {{
            font-size: 13px;
            opacity: 0.85;
            text-transform: uppercase;
            font-weight: 500;
        }}

        /* Progress Bar */
        .progress-section {{
            margin-bottom: 40px;
            animation: slideUp 0.8s ease-out 0.1s backwards;
        }}

        .progress-label {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
        }}

        .progress-label-text {{
            font-size: 13px;
            font-weight: 600;
            color: var(--slate-300);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .progress-value {{
            font-size: 18px;
            font-weight: 700;
            color: white;
            font-family: 'JetBrains Mono', monospace;
        }}

        .progress {{
            height: 24px;
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            overflow: hidden;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }}

        .progress-fill {{
            height: 100%;
            width: {min(total_score,100)}%;
            background: linear-gradient(90deg, {risk_color} 0%, {accent} 100%);
            border-radius: 12px;
            transition: width 1.5s cubic-bezier(0.34, 1.56, 0.64, 1);
            box-shadow: 0 0 20px rgba(0,0,0,0.3);
        }}

        /* Cards Grid */
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
            animation: slideUp 0.8s ease-out 0.15s backwards;
        }}

        .card {{
            background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 28px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }}

        .card:hover {{
            border-color: {risk_color};
            background: linear-gradient(135deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.04) 100%);
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(0,0,0,0.2);
        }}

        .card-icon {{
            width: 48px;
            height: 48px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
            font-size: 24px;
        }}

        .card.critical .card-icon {{
            background: rgba(239, 68, 68, 0.15);
        }}

        .card.high .card-icon {{
            background: rgba(245, 158, 11, 0.15);
        }}

        .card.medium .card-icon {{
            background: rgba(59, 130, 246, 0.15);
        }}

        .card.low .card-icon {{
            background: rgba(16, 185, 129, 0.15);
        }}

        .card-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--slate-400);
            margin-bottom: 8px;
        }}

        .card-value {{
            font-size: 36px;
            font-weight: 700;
            color: white;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* Metadata Section */
        .section {{
            background: linear-gradient(135deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.01) 100%);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 36px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            animation: slideUp 0.8s ease-out 0.2s backwards;
        }}

        .section-title {{
            font-size: 20px;
            font-weight: 700;
            color: white;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .section-title::before {{
            content: '';
            display: inline-block;
            width: 4px;
            height: 24px;
            background: linear-gradient(180deg, {risk_color} 0%, {accent} 100%);
            border-radius: 2px;
        }}

        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}

        .metadata-item {{
            display: flex;
            flex-direction: column;
        }}

        .metadata-key {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--slate-400);
            margin-bottom: 8px;
        }}

        .metadata-value {{
            font-size: 15px;
            font-weight: 600;
            color: white;
            font-family: 'JetBrains Mono', monospace;
            word-break: break-all;
        }}

        /* Search Bar */
        .search-container {{
            margin-bottom: 30px;
            animation: slideUp 0.8s ease-out 0.25s backwards;
        }}

        .search-box {{
            width: 100%;
            padding: 14px 20px;
            background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            color: white;
            font-family: 'Outfit', sans-serif;
            font-size: 15px;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }}

        .search-box:focus {{
            outline: none;
            border-color: {risk_color};
            background: linear-gradient(135deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.04) 100%);
            box-shadow: 0 0 20px rgba({risk_color}, 0.2);
        }}

        .search-box::placeholder {{
            color: var(--slate-500);
        }}

        /* Findings */
        .finding {{
            background: linear-gradient(135deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.01) 100%);
            border: 1px solid rgba(255,255,255,0.1);
            border-left: 4px solid var(--primary);
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            animation: slideUp 0.6s ease-out backwards;
        }}

        .finding:nth-child(1) {{ animation-delay: 0.3s; }}
        .finding:nth-child(2) {{ animation-delay: 0.35s; }}
        .finding:nth-child(3) {{ animation-delay: 0.4s; }}
        .finding:nth-child(4) {{ animation-delay: 0.45s; }}
        .finding:nth-child(5) {{ animation-delay: 0.5s; }}

        .finding.critical {{
            border-left-color: #ef4444;
        }}

        .finding.high {{
            border-left-color: #f59e0b;
        }}

        .finding.medium {{
            border-left-color: #3b82f6;
        }}

        .finding.low {{
            border-left-color: #10b981;
        }}

        .finding:hover {{
            transform: translateX(4px);
            border-color: var(--primary);
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }}

        .finding-header {{
            background: linear-gradient(90deg, rgba(0,0,0,0.2) 0%, rgba(0,0,0,0.05) 100%);
            padding: 18px 24px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            user-select: none;
            transition: all 0.3s ease;
        }}

        .finding-header:hover {{
            background: linear-gradient(90deg, rgba(0,0,0,0.3) 0%, rgba(0,0,0,0.1) 100%);
        }}

        .finding-title {{
            font-size: 15px;
            font-weight: 600;
            color: white;
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }}

        .finding-severity {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 6px 12px;
            border-radius: 6px;
            background: var(--primary-light);
            color: var(--primary);
            margin-right: 12px;
        }}

        .finding-toggle {{
            font-size: 16px;
            color: var(--slate-400);
            transition: transform 0.3s ease;
        }}

        .finding-body {{
            display: none;
            padding: 24px;
            background: rgba(0,0,0,0.2);
            border-top: 1px solid rgba(255,255,255,0.1);
        }}

        .finding-body.active {{
            display: block;
            animation: slideDown 0.3s ease-out;
        }}

        .finding-detail {{
            margin-bottom: 16px;
        }}

        .finding-detail:last-child {{
            margin-bottom: 0;
        }}

        .finding-detail-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--slate-400);
            margin-bottom: 8px;
        }}

        .finding-detail-text {{
            font-size: 14px;
            color: var(--slate-100);
            line-height: 1.6;
        }}

        /* Download Buttons */
        .download-buttons {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 40px;
            animation: slideUp 0.8s ease-out 0.3s backwards;
        }}

        .btn {{
            padding: 12px 24px;
            border: none;
            border-radius: 10px;
            font-family: 'Outfit', sans-serif;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
        }}

        .btn-primary {{
            background: linear-gradient(135deg, {risk_color} 0%, {accent} 100%);
            color: white;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }}

        .btn-primary:hover {{
            transform: translateY(-2px);
            box-shadow: 0 12px 32px rgba(0,0,0,0.3);
        }}

        .btn-secondary {{
            background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%);
            color: white;
            border: 1px solid rgba(255,255,255,0.2);
        }}

        .btn-secondary:hover {{
            background: linear-gradient(135deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.08) 100%);
            border-color: {risk_color};
            transform: translateY(-2px);
        }}

        /* Grade Badge */
        .grade-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100px;
            height: 100px;
            border-radius: 12px;
            background: linear-gradient(135deg, {risk_color} 0%, {accent} 100%);
            color: white;
            font-size: 48px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            box-shadow: 0 12px 32px rgba(0,0,0,0.2);
        }}

        /* Animations */
        @keyframes slideDown {{
            from {{
                opacity: 0;
                transform: translateY(-20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        @keyframes float {{
            0%, 100% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(20px); }}
        }}

        /* Summary Stats */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-top: 24px;
        }}

        .summary-stat {{
            background: rgba(0,0,0,0.2);
            padding: 16px;
            border-radius: 10px;
            border: 1px solid rgba(255,255,255,0.05);
            text-align: center;
        }}

        .summary-stat-value {{
            font-size: 24px;
            font-weight: 700;
            color: white;
            font-family: 'JetBrains Mono', monospace;
            margin-bottom: 4px;
        }}

        .summary-stat-label {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--slate-400);
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .header-top {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .header-text h1 {{
                font-size: 32px;
            }}

            .risk-level {{
                font-size: 36px;
            }}

            .cards-grid {{
                grid-template-columns: 1fr;
            }}

            .metadata-grid {{
                grid-template-columns: 1fr;
            }}

            .download-buttons {{
                flex-direction: column;
            }}

            .btn {{
                width: 100%;
                justify-content: center;
            }}
        }}
    </style>
</head>

<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-top">
                <div class="logo-icon">🔐</div>
                <div class="header-text">
                    <h1>APK Sentinel</h1>
                    <p>Security Report</p>
                </div>
            </div>
        </div>

        <!-- Risk Banner -->
        <div class="risk-banner">
            <div class="risk-content">
                <div class="risk-label">Overall Assessment</div>
                <div class="risk-level">{risk_level}</div>
                <div class="risk-score">
                    <div class="score-item">
                        <div class="score-number">{total_score}</div>
                        <div class="score-label">Risk Score</div>
                    </div>
                    <div class="score-item">
                        <div class="score-number">{grade}</div>
                        <div class="score-label">Security Grade</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Progress Bar -->
        <div class="progress-section">
            <div class="progress-label">
                <span class="progress-label-text">Risk Score Distribution</span>
                <span class="progress-value">{min(total_score, 100)}/100</span>
            </div>
            <div class="progress">
                <div class="progress-fill"></div>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="cards-grid">
            <div class="card critical">
                <div class="card-icon">🔴</div>
                <div class="card-label">Critical</div>
                <div class="card-value">{critical_count}</div>
            </div>
            <div class="card high">
                <div class="card-icon">🟠</div>
                <div class="card-label">High</div>
                <div class="card-value">{high_count}</div>
            </div>
            <div class="card medium">
                <div class="card-icon">🔵</div>
                <div class="card-label">Medium</div>
                <div class="card-value">{medium_count}</div>
            </div>
            <div class="card low">
                <div class="card-icon">🟢</div>
                <div class="card-label">Low</div>
                <div class="card-value">{low_count}</div>
            </div>
        </div>

        <!-- Download Section -->
        <div class="download-buttons">
            <button class="btn btn-primary" onclick="downloadFile('report.html')">📄 Download HTML</button>
            <button class="btn btn-primary" onclick="downloadFile('report.pdf')">📋 Download PDF</button>
            <button class="btn btn-primary" onclick="downloadFile('report.json')">📊 Download JSON</button>
        </div>

        <!-- Metadata Section -->
        <div class="section">
            <div class="section-title">Application Metadata</div>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-key">Package Name</div>
                    <div class="metadata-value">{metadata['package_name']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-key">Version</div>
                    <div class="metadata-value">{metadata['version_name']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-key">Minimum SDK</div>
                    <div class="metadata-value">{metadata['min_sdk']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-key">Total Permissions</div>
                    <div class="metadata-value">{metadata['permissions_count']}</div>
                </div>
            </div>
        </div>

        <!-- Summary Section -->
        <div class="section">
            <div class="section-title">Executive Summary</div>
            <p style="color: var(--slate-200); line-height: 1.8; margin-bottom: 20px;">{risk_reason}</p>
            <div class="summary-grid">
                <div class="summary-stat">
                    <div class="summary-stat-value">{total_score}</div>
                    <div class="summary-stat-label">Risk Score</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value">{critical_count}</div>
                    <div class="summary-stat-label">Critical</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value">{high_count}</div>
                    <div class="summary-stat-label">High</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value">{medium_count}</div>
                    <div class="summary-stat-label">Medium</div>
                </div>
            </div>
        </div>

        <!-- Search Section -->
        <div class="search-container">
            <input 
                type="text" 
                class="search-box" 
                id="search" 
                onkeyup="searchFindings()" 
                placeholder="Search findings by title, description, or remediation..."
            >
        </div>

        <!-- Findings Section -->
        <div class="section">
            <div class="section-title">Detailed Findings</div>
            <div id="findingsContainer">
"""

    for i, f in enumerate(findings):
        severity_class = f['severity'].lower()
        html += f"""
                <div class="finding {severity_class}">
                    <div class="finding-header" onclick="toggleFinding(this)">
                        <div class="finding-title">
                            <span class="finding-severity">{f['severity']}</span>
                            <span>{f['title']}</span>
                        </div>
                        <div class="finding-toggle">▼</div>
                    </div>
                    <div class="finding-body" data-searchtext="{f['title'].lower()} {f['description'].lower()} {f['remediation'].lower()}">
                        <div class="finding-detail">
                            <div class="finding-detail-label">OWASP Category</div>
                            <div class="finding-detail-text">{f['owasp']}</div>
                        </div>
                        <div class="finding-detail">
                            <div class="finding-detail-label">Description</div>
                            <div class="finding-detail-text">{f['description']}</div>
                        </div>
                        <div class="finding-detail">
                            <div class="finding-detail-label">Remediation</div>
                            <div class="finding-detail-text">{f['remediation']}</div>
                        </div>
                    </div>
                </div>
"""

    html += """
            </div>
        </div>

        <!-- Footer -->
        <div style="text-align: center; margin-top: 60px; padding-top: 40px; border-top: 1px solid rgba(255,255,255,0.1);">
            <p style="color: var(--slate-400); font-size: 13px;">
                Generated on """ + str(datetime.now()) + """<br>
                APK Sentinel Security Report
            </p>
        </div>
    </div>

    <script>
        function toggleFinding(element) {
            const body = element.nextElementSibling;
            const toggle = element.querySelector('.finding-toggle');
            
            body.classList.toggle('active');
            toggle.style.transform = body.classList.contains('active') ? 'rotate(180deg)' : 'rotate(0deg)';
        }

        function searchFindings() {
            const input = document.getElementById('search').value.toLowerCase();
            const findings = document.querySelectorAll('.finding');
            
            findings.forEach(finding => {
                const body = finding.querySelector('.finding-body');
                const searchText = body.getAttribute('data-searchtext');
                
                if (searchText.includes(input) || input === '') {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }

        function downloadFile(filename) {
            const link = document.createElement('a');
            link.href = filename;
            link.download = filename;
            link.click();
        }

        // Animate progress bar on load
        window.addEventListener('load', () => {
            const progressFill = document.querySelector('.progress-fill');
            setTimeout(() => {
                progressFill.style.width = '{min(total_score,100)}%';
            }, 100);
        });
    </script>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print("[+] HTML, PDF, and JSON reports generated successfully.")