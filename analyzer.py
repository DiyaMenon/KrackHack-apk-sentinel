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

WEAK_CRYPTO_PATTERNS = rb"(MD5|SHA1|DES)"

SECRET_PATTERNS = rb"(api[_-]?key\s*=\s*|secret\s*=\s*|token\s*=\s*|password\s*=\s*)"


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

    a = APK(apk_path)

    # -----------------------
    #Debuggable Check
    # -----------------------
    if a.get_attribute_value("application", "debuggable") == "true":
        findings.append(create_finding(
            "Application is debuggable",
            "High",
            "M1: Improper Platform Usage",
            "The application is built in debug mode.",
            "Disable android:debuggable in production builds."
        ))

    # -----------------------
    #Dangerous Permissions
    # -----------------------
    permissions = a.get_permissions()

    dangerous_count = 0

    for perm in permissions:
        for dangerous in DANGEROUS_PERMISSIONS:
            if dangerous in perm:
                dangerous_count += 1
                findings.append(create_finding(
                    f"Dangerous permission detected: {dangerous}",
                    "Medium",
                    "M2: Insecure Data Storage",
                    f"The app requests {dangerous}.",
                    "Ensure this permission is strictly necessary."
                ))

    if dangerous_count > 3:
        findings.append(create_finding(
            "Excessive dangerous permissions",
            "High",
            "M2: Insecure Data Storage",
            "Application requests multiple dangerous permissions.",
            "Follow the principle of least privilege."
        ))

    # -----------------------
    #Exported Components
    # -----------------------
    manifest = a.get_android_manifest_xml()

    for tag in ["activity", "service", "receiver", "provider"]:
        for element in manifest.findall(f".//{tag}"):
            exported = element.get("{http://schemas.android.com/apk/res/android}exported")
            if exported == "true":
                findings.append(create_finding(
                    f"Exported {tag} detected",
                    "High",
                    "M1: Improper Platform Usage",
                    f"{tag} is exported and may be externally accessible.",
                    "Ensure exported components are protected with permissions."
                ))

    # -----------------------
    #allowBackup Check
    # -----------------------
    if a.get_attribute_value("application", "allowBackup") == "true":
        findings.append(create_finding(
            "Application allows backup",
            "Medium",
            "M2: Insecure Data Storage",
            "Application data can be backed up via ADB.",
            "Set android:allowBackup=\"false\" in production."
        ))

    # -----------------------
    #Cleartext Traffic
    # -----------------------
    if a.get_attribute_value("application", "usesCleartextTraffic") == "true":
        findings.append(create_finding(
            "Cleartext traffic allowed",
            "High",
            "M3: Insecure Communication",
            "Application allows HTTP traffic without encryption.",
            "Disable cleartext traffic and enforce HTTPS."
        ))

    # -----------------------
    #Lightweight DEX Scan
    # -----------------------
    for file_name in a.get_files():
        if file_name.endswith(".dex"):
            dex_data = a.get_file(file_name)

            if re.search(SECRET_PATTERNS, dex_data, re.IGNORECASE):
                findings.append(create_finding(
                    "Potential hardcoded secret detected",
                    "Critical",
                    "M9: Reverse Engineering",
                    "Suspicious credential pattern found in DEX file.",
                    "Move secrets to secure backend storage."
                ))

            if re.search(WEAK_CRYPTO_PATTERNS, dex_data):
                findings.append(create_finding(
                    "Weak cryptographic algorithm detected",
                    "High",
                    "M5: Insufficient Cryptography",
                    "Weak algorithm reference found (MD5/SHA1/DES).",
                    "Use strong algorithms like SHA-256 or AES."
                ))

    return findings