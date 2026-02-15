from datetime import datetime
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
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
        return "Critical vulnerabilities detected. Immediate remediation is strictly required before any production deployment."
    if high_count >= 5:
        return "Multiple high-severity issues identified. Attack surface is significantly expanded, risking data exposure."
    if total_score > 50:
        return "Accumulated risk score indicates widespread security misconfigurations across the application architecture."
    return "Acceptable baseline security posture. Standard remediation of medium/low findings is recommended during the next sprint."

# ----------------------------------
# Premium PDF Generator
# ----------------------------------

def generate_pdf(findings, metadata, total_score, risk_level, grade, risk_color_hex):
    doc = SimpleDocTemplate("report.pdf", pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    # Custom PDF Styles
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=20
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=20,
        spaceAfter=10,
        borderPadding=10,
    )

    normal_style = styles["Normal"]
    elements = []

    # --- COVER SECTION ---
    elements.append(Paragraph("🔒 APK Sentinel Security Audit", title_style))
    elements.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 20))

    # --- METADATA & RISK SCORE TABLE ---
    summary_data = [
        ["Target Package", metadata.get('package_name', 'N/A'), "Risk Level", risk_level],
        ["App Version", metadata.get('version_name', 'N/A'), "Security Grade", grade],
        ["Target SDK", metadata.get('target_sdk', 'N/A'), "Total Score", str(total_score)]
    ]
    
    summary_table = Table(summary_data, colWidths=[100, 160, 100, 160])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
        ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f8fafc')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#334155')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 30))

    # --- DETAILED FINDINGS ---
    elements.append(Paragraph("Detailed Vulnerability Findings", heading_style))
    
    color_map = {
        "Critical": colors.HexColor("#ef4444"),
        "High": colors.HexColor("#f97316"),
        "Medium": colors.HexColor("#3b82f6"),
        "Low": colors.HexColor("#10b981")
    }

    for f in findings:
        sev_color = color_map.get(f['severity'], colors.gray)
        
        finding_data = [
            [Paragraph(f"<b>[{f['severity'].upper()}] {f['title']}</b>", styles['Normal']), ""],
            ["OWASP Category", Paragraph(f['owasp'], styles['Normal'])],
            ["Description", Paragraph(f['description'], styles['Normal'])],
            ["Remediation", Paragraph(f['remediation'], styles['Normal'])]
        ]
        
        t = Table(finding_data, colWidths=[100, 420])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), sev_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('SPAN', (0, 0), (1, 0)), 
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f8fafc')),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(t)
        elements.append(Spacer(1, 15))

    doc.build(elements)


# ----------------------------------
# Main Report Generator (HTML/JSON)
# ----------------------------------

def generate_report(findings, metadata, output_file="report.html"):

    total_score = sum(SEVERITY_SCORES.get(f["severity"], 0) for f in findings)

    # Dark Mode Color scaling
    if total_score > 60:
        risk_level = "Critical Risk"
        risk_color = "#ef4444" # Bright Red
        risk_bg = "rgba(239, 68, 68, 0.15)" # Translucent Red Overlay
    elif total_score > 25:
        risk_level = "Elevated Risk"
        risk_color = "#f97316" # Bright Orange
        risk_bg = "rgba(249, 115, 22, 0.15)"
    else:
        risk_level = "Acceptable Risk"
        risk_color = "#10b981" # Bright Green
        risk_bg = "rgba(16, 185, 129, 0.15)"

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
    generate_pdf(findings, metadata, total_score, risk_level, grade, risk_color)

    # --- HTML DARK MODE WHITEPAPER GENERATION ---
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Sentinel | Audit Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

        :root {{
            --primary: {risk_color};
            --bg-color: #0b0f19;        /* Deep space background */
            --doc-bg: #111827;          /* Dark paper background */
            --panel-bg: #1f2937;        /* Slightly lighter dark for headers/tables */
            --text-main: #f3f4f6;       /* Crisp off-white text */
            --text-muted: #9ca3af;      /* Muted gray text */
            --border: #374151;          /* Dark gray borders */
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.6;
            padding: 40px 20px;
        }}

        /* The 'Physical Paper' Container */
        .document-container {{
            max-width: 900px;
            margin: 0 auto;
            background: var(--doc-bg);
            padding: 60px 80px;
            border-radius: 8px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
            border-top: 8px solid var(--primary);
            border-left: 1px solid var(--border);
            border-right: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
        }}

        /* Header / Letterhead */
        .letterhead {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 50px;
            padding-bottom: 30px;
            border-bottom: 2px solid var(--border);
        }}

        .brand h1 {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.5px;
            margin-bottom: 4px;
        }}

        .brand p {{
            font-size: 14px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 600;
        }}

        .meta-stamp {{
            text-align: right;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-muted);
        }}

        /* Executive Summary Banner */
        .exec-summary {{
            background: {risk_bg};
            border: 1px solid var(--primary);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 40px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .grade-circle {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: var(--primary);
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            font-weight: 700;
            box-shadow: 0 0 20px {risk_bg};
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}

        .exec-details h2 {{
            font-size: 24px;
            color: var(--primary);
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.5);
        }}

        .exec-details p {{
            font-size: 15px;
            color: var(--text-main);
            max-width: 500px;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 40px;
        }}

        .stat-box {{
            background: var(--panel-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}

        .stat-number {{
            font-size: 32px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-main);
        }}

        .stat-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            margin-top: 4px;
        }}

        /* Tables */
        h3.section-title {{
            font-size: 18px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 20px;
            margin-top: 40px;
        }}

        .info-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 40px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}

        .info-table th, .info-table td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            text-align: left;
            font-size: 14px;
        }}

        .info-table th {{
            width: 30%;
            background: var(--panel-bg);
            color: var(--text-muted);
            font-weight: 600;
        }}

        .info-table td {{
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-main);
            word-break: break-all;
            background: var(--doc-bg);
        }}

        /* Vulnerability Findings Styling */
        .finding-card {{
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
            page-break-inside: avoid;
            background: var(--doc-bg);
        }}

        .finding-header {{
            padding: 16px 20px;
            background: var(--panel-bg);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .severity-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: #ffffff;
            letter-spacing: 0.5px;
        }}
        .badge-critical {{ background-color: #ef4444; box-shadow: 0 0 10px rgba(239,68,68,0.3); }}
        .badge-high {{ background-color: #f97316; box-shadow: 0 0 10px rgba(249,115,22,0.3); }}
        .badge-medium {{ background-color: #3b82f6; box-shadow: 0 0 10px rgba(59,130,246,0.3); }}
        .badge-low {{ background-color: #10b981; box-shadow: 0 0 10px rgba(16,185,129,0.3); }}

        .finding-title {{
            font-weight: 600;
            font-size: 16px;
            color: var(--text-main);
        }}

        .finding-body {{
            padding: 0;
        }}

        .finding-row {{
            display: flex;
            border-bottom: 1px solid var(--border);
        }}
        .finding-row:last-child {{ border-bottom: none; }}

        .row-label {{
            width: 140px;
            padding: 16px 20px;
            background: var(--panel-bg);
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            border-right: 1px solid var(--border);
        }}

        .row-content {{
            flex: 1;
            padding: 16px 20px;
            font-size: 14px;
        }}

        /* Print CSS: Forces white background and black text when exporting via browser! */
        @media print {{
            :root {{
                --bg-color: #ffffff;
                --doc-bg: #ffffff;
                --panel-bg: #f8fafc;
                --text-main: #000000;
                --text-muted: #475569;
                --border: #cbd5e1;
            }}
            body {{
                background: white;
                padding: 0;
            }}
            .document-container {{
                box-shadow: none;
                padding: 0;
                border: none;
                border-top: 8px solid var(--primary);
                max-width: 100%;
            }}
            .finding-card {{
                break-inside: avoid;
            }}
            .grade-circle {{
                box-shadow: none;
                text-shadow: none;
            }}
            .exec-details h2 {{
                text-shadow: none;
            }}
        }}
    </style>
</head>
<body>

    <div class="document-container">
        
        <div class="letterhead">
            <div class="brand">
                <h1>APK Sentinel</h1>
                <p>Automated Security Audit Report</p>
            </div>
            <div class="meta-stamp">
                ID: {datetime.now().strftime('%Y%m%d')}-SAST<br>
                DATE: {datetime.now().strftime('%b %d, %Y')}<br>
                STATUS: FINAL
            </div>
        </div>

        <div class="exec-summary">
            <div class="exec-details">
                <h2>{risk_level}</h2>
                <p>{risk_reason}</p>
            </div>
            <div class="grade-circle">{grade}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-number">{critical_count}</div>
                <div class="stat-label" style="color: #ef4444;">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{high_count}</div>
                <div class="stat-label" style="color: #f97316;">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{medium_count}</div>
                <div class="stat-label" style="color: #3b82f6;">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{low_count}</div>
                <div class="stat-label" style="color: #10b981;">Low</div>
            </div>
        </div>

        <h3 class="section-title">1. Target Information</h3>
        <table class="info-table">
            <tr>
                <th>Package Name</th>
                <td>{metadata.get('package_name', 'Unknown')}</td>
            </tr>
            <tr>
                <th>Version String</th>
                <td>{metadata.get('version_name', 'Unknown')}</td>
            </tr>
            <tr>
                <th>Target SDK</th>
                <td>API {metadata.get('target_sdk', 'Unknown')}</td>
            </tr>
            <tr>
                <th>Permissions Requested</th>
                <td>{metadata.get('permissions_count', 'Unknown')}</td>
            </tr>
        </table>

        <h3 class="section-title">2. Vulnerability Log</h3>
"""

    # Generate Finding Cards
    for f in findings:
        sev_class = f"badge-{f['severity'].lower()}"
        html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="severity-badge {sev_class}">{f['severity']}</span>
                <span class="finding-title">{f['title']}</span>
            </div>
            <div class="finding-body">
                <div class="finding-row">
                    <div class="row-label">Category</div>
                    <div class="row-content" style="font-family: 'JetBrains Mono', monospace;">{f['owasp']}</div>
                </div>
                <div class="finding-row">
                    <div class="row-label">Description</div>
                    <div class="row-content">{f['description']}</div>
                </div>
                <div class="finding-row">
                    <div class="row-label">Remediation</div>
                    <div class="row-content" style="color: #34d399; font-weight: 500;">{f['remediation']}</div>
                </div>
            </div>
        </div>
"""

    html += """
        <div style="text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 12px;">
            End of Report • Generated by APK Sentinel
        </div>
    </div>

</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print("[+] HTML, PDF, and JSON reports generated successfully.")