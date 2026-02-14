from androguard.misc import AnalyzeAPK
import re
import logging
logging.getLogger("androguard").setLevel(logging.CRITICAL)

DANGEROUS_PERMISSIONS = [
    "READ_SMS",
    "SEND_SMS",
    "READ_CONTACTS",
    "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION",
    "WRITE_EXTERNAL_STORAGE"
]

def create_finding(title, severity, owasp, description, remediation):
    return {
        "title": title,
        "severity": severity,
        "owasp": owasp,
        "description": description,
        "remediation": remediation
    }

def analyze_apk(apk_path):
    findings = []

    print("[+] Loading APK...")
    a, d, dx = AnalyzeAPK(apk_path)

    # 1. Debuggable check (manual)
    debuggable = a.get_attribute_value("application", "debuggable")

    if debuggable == "true":
        findings.append(create_finding(
            "Application is debuggable",
            "High",
            "M1: Improper Platform Usage",
            "The application is built in debug mode.",
            "Disable android:debuggable in production builds."
        ))
    
    # 2. Dangerous permissions
    permissions = a.get_permissions()
    for perm in permissions:
        for dangerous in DANGEROUS_PERMISSIONS:
            if dangerous in perm:
                findings.append(create_finding(
                    f"Dangerous permission detected: {dangerous}",
                    "Medium",
                    "M2: Insecure Data Storage",
                    f"The app requests {dangerous}.",
                    "Ensure this permission is necessary."
                ))

    # 3. Hardcoded secrets
    for string_obj in dx.get_strings():
        string_value = string_obj.get_value()

        if string_value and re.search(r"(API_KEY|SECRET|TOKEN|PASSWORD)", string_value, re.IGNORECASE):
            findings.append(create_finding(
                "Potential hardcoded secret detected",
                "Critical",
                "M9: Reverse Engineering",
                f"Suspicious string found: {string_value}",
                "Move secrets to secure backend storage."
            ))
            break
    # 4. allowBackup check
    if a.get_attribute_value("application", "allowBackup") == "true":
        findings.append(create_finding(
            "Application allows backup",
            "Medium",
            "M2: Insecure Data Storage",
            "Application data can be backed up via ADB.",
            "Set android:allowBackup=\"false\" in production."
        ))
    # 5. Cleartext traffic check
    if a.get_attribute_value("application", "usesCleartextTraffic") == "true":
        findings.append(create_finding(
            "Cleartext traffic allowed",
            "High",
            "M3: Insecure Communication",
            "Application allows HTTP traffic without encryption.",
            "Disable cleartext traffic and enforce HTTPS."
        ))
    return findings