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
        risk_level = "High"
    elif total_score > 10:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    html = f"""
    <html>
    <head>
        <title>APK Security Report</title>
        <style>
            body {{ font-family: Arial; padding: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Mobile App Security Report</h1>
        <p><strong>Date:</strong> {datetime.now()}</p>
        <p><strong>Total Risk Score:</strong> {total_score}</p>
        <p><strong>Overall Risk Level:</strong> {risk_level}</p>

        <h2>Findings</h2>
        <table>
            <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>OWASP</th>
                <th>Description</th>
                <th>Remediation</th>
            </tr>
    """

    for f in findings:
        html += f"""
            <tr>
                <td>{f['title']}</td>
                <td>{f['severity']}</td>
                <td>{f['owasp']}</td>
                <td>{f['description']}</td>
                <td>{f['remediation']}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)

    print(f"[+] Report saved as {output_file}")