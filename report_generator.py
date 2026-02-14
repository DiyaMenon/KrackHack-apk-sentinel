from datetime import datetime

SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}

def generate_report(findings, output_file="report.html"):

    total_score = sum(SEVERITY_SCORES.get(f["severity"], 0) for f in findings)

    if total_score > 25:
        risk_level = "High Risk"
    elif total_score > 10:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    critical_count = sum(1 for f in findings if f["severity"] == "Critical")
    high_count = sum(1 for f in findings if f["severity"] == "High")
    medium_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")

    html = f"""
    <html>
    <head>
        <title>APK Sentinel Security Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 30px;
                background-color: #f4f6f9;
            }}
            h1 {{
                color: #2c3e50;
            }}
            .summary-box {{
                background: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            th, td {{
                padding: 12px;
                text-align: left;
            }}
            th {{
                background-color: #34495e;
                color: white;
            }}
            tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
        </style>
    </head>
    <body>

        <h1>📱 APK Sentinel Security Report</h1>
        <p><strong>Generated On:</strong> {datetime.now()}</p>

        <div class="summary-box">
            <h2>Executive Summary</h2>
            <p><strong>Total Risk Score:</strong> {total_score}</p>
            <p><strong>Overall Risk Level:</strong> {risk_level}</p>
            <p><strong>Critical:</strong> {critical_count}</p>
            <p><strong>High:</strong> {high_count}</p>
            <p><strong>Medium:</strong> {medium_count}</p>
            <p><strong>Low:</strong> {low_count}</p>
        </div>

        <h2>Detailed Findings</h2>

        <table>
            <tr>
                <th>Issue</th>
                <th>Severity</th>
                <th>OWASP Category</th>
                <th>Description</th>
                <th>Remediation</th>
            </tr>
    """

    for f in findings:
        color = {
            "Critical": "#ff4d4d",
            "High": "#ff944d",
            "Medium": "#ffd11a",
            "Low": "#b3ff66"
        }.get(f["severity"], "#ffffff")

        html += f"""
            <tr>
                <td>{f['title']}</td>
                <td style="background-color:{color}; font-weight:bold;">
                    {f['severity']}
                </td>
                <td>{f['owasp']}</td>
                <td>{f['description']}</td>
                <td>{f['remediation']}</td>
            </tr>
        """

    html += """
        </table>

        <p style="margin-top:30px; font-size: 14px; color: gray;">
        This report was generated using static analysis techniques. 
        Findings indicate potential security risks and should be reviewed by developers.
        </p>

    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)

    print(f"[+] Report saved as {output_file}")