from androguard.core.apk import APK
import re
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
    a = APK(apk_path)

    #Debuggable Check
    if a.get_attribute_value("application", "debuggable") == "true":
        findings.append(create_finding(
            "Application is debuggable",
            "High",
            "M1: Improper Platform Usage",
            "The application is built in debug mode.",
            "Disable android:debuggable in production builds."
        ))

    #Dangerous Permissions Check
    permissions = a.get_permissions()
    for perm in permissions:
        for dangerous in DANGEROUS_PERMISSIONS:
            if dangerous in perm:
                findings.append(create_finding(
                    f"Dangerous permission detected: {dangerous}",
                    "Medium",
                    "M2: Insecure Data Storage",
                    f"The app requests {dangerous}.",
                    "Ensure this permission is absolutely necessary."
                ))

    #allowBackup Check
    if a.get_attribute_value("application", "allowBackup") == "true":
        findings.append(create_finding(
            "Application allows backup",
            "Medium",
            "M2: Insecure Data Storage",
            "Application data can be backed up via ADB.",
            "Set android:allowBackup=\"false\" in production."
        ))

    #Cleartext Traffic Check
    if a.get_attribute_value("application", "usesCleartextTraffic") == "true":
        findings.append(create_finding(
            "Cleartext traffic allowed",
            "High",
            "M3: Insecure Communication",
            "Application allows HTTP traffic without encryption.",
            "Disable cleartext traffic and enforce HTTPS."
        ))

    #Lightweight Hardcoded Secret Scan (No Heavy dx Analysis)
    for file_name in a.get_files():
        if file_name.endswith(".dex"):
            dex_data = a.get_file(file_name)
            if re.search(rb"(API_KEY|SECRET|TOKEN|PASSWORD)", dex_data, re.IGNORECASE):
                findings.append(create_finding(
                    "Potential hardcoded secret detected",
                    "Critical",
                    "M9: Reverse Engineering",
                    "Suspicious keyword found inside DEX file.",
                    "Move secrets to secure backend storage."
                ))
                break

    return findings