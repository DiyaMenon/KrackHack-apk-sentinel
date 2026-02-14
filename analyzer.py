from androguard.core.apk import APK
import re

# ----------------------------------
# Dangerous Permissions
# ----------------------------------

DANGEROUS_PERMISSIONS = [
    "READ_SMS",
    "SEND_SMS",
    "READ_CONTACTS",
    "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION",
    "WRITE_EXTERNAL_STORAGE"
]

# ----------------------------------
# DEX Scan Patterns
# ----------------------------------

WEAK_CRYPTO_PATTERNS = rb"(MD5|SHA1|DES)"
SECRET_PATTERNS = rb"(api[_-]?key\s*=\s*|secret\s*=\s*|token\s*=\s*|password\s*=\s*)"

WEBVIEW_JS_PATTERN = rb"setJavaScriptEnabled"
WEBVIEW_INTERFACE_PATTERN = rb"addJavascriptInterface"
WEBVIEW_HTTP_PATTERN = rb'loadUrl\("http://'

HTTP_URL_PATTERN = rb"http://[^\s\"']+"
IP_ADDRESS_PATTERN = rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"
FIREBASE_PATTERN = rb"\.firebaseio\.com"
AWS_PATTERN = rb"s3\.amazonaws\.com"


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

    # ----------------------------------
    # Debuggable Check
    # ----------------------------------

    if a.get_attribute_value("application", "debuggable") == "true":
        findings.append(create_finding(
            "Application is debuggable",
            "High",
            "M1: Improper Platform Usage",
            "The application is built in debug mode.",
            "Disable android:debuggable in production builds."
        ))

    # ----------------------------------
    # Dangerous Permissions
    # ----------------------------------

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

    # ----------------------------------
    # Exported Components
    # ----------------------------------

    manifest = a.get_android_manifest_xml()

    for tag in ["activity", "service", "receiver", "provider"]:
        for element in manifest.findall(f".//{tag}"):
            exported = element.get("{http://schemas.android.com/apk/res/android}exported")
            name = element.get("{http://schemas.android.com/apk/res/android}name")

            if exported == "true":
                findings.append(create_finding(
                    f"Exported {tag} detected: {name}",
                    "High",
                    "M1: Improper Platform Usage",
                    f"{tag} '{name}' is exported and may be externally accessible.",
                    "Ensure exported components are protected with proper permissions."
                ))

    # ----------------------------------
    # allowBackup Check
    # ----------------------------------

    if a.get_attribute_value("application", "allowBackup") == "true":
        findings.append(create_finding(
            "Application allows backup",
            "Medium",
            "M2: Insecure Data Storage",
            "Application data can be backed up via ADB.",
            "Set android:allowBackup=\"false\" in production."
        ))

    # ----------------------------------
    # Cleartext Traffic
    # ----------------------------------

    if a.get_attribute_value("application", "usesCleartextTraffic") == "true":
        findings.append(create_finding(
            "Cleartext traffic allowed",
            "High",
            "M3: Insecure Communication",
            "Application allows HTTP traffic without encryption.",
            "Disable cleartext traffic and enforce HTTPS."
        ))

    # ----------------------------------
    # DEX Scan Section
    # ----------------------------------

    secret_found = False
    crypto_found = False
    webview_js_found = False
    webview_interface_found = False
    webview_http_found = False
    http_found = False
    ip_found = False
    firebase_found = False
    aws_found = False

    for file_name in a.get_files():

        if file_name.endswith(".dex"):

            dex_data = a.get_file(file_name)

            # Hardcoded Secrets
            if not secret_found and re.search(SECRET_PATTERNS, dex_data, re.IGNORECASE):
                secret_found = True
                findings.append(create_finding(
                    "Potential hardcoded secret detected",
                    "Critical",
                    "M9: Reverse Engineering",
                    "Suspicious credential pattern found in DEX file.",
                    "Move secrets to secure backend storage."
                ))

            # Weak Crypto
            if not crypto_found and re.search(WEAK_CRYPTO_PATTERNS, dex_data):
                crypto_found = True
                findings.append(create_finding(
                    "Weak cryptographic algorithm detected",
                    "High",
                    "M5: Insufficient Cryptography",
                    "Weak algorithm reference found (MD5/SHA1/DES).",
                    "Use strong algorithms like SHA-256 or AES."
                ))

            # WebView JavaScript
            if not webview_js_found and re.search(WEBVIEW_JS_PATTERN, dex_data):
                webview_js_found = True
                findings.append(create_finding(
                    "WebView JavaScript Enabled",
                    "High",
                    "M1: Improper Platform Usage",
                    "WebView enables JavaScript which increases attack surface.",
                    "Disable JavaScript unless absolutely necessary."
                ))

            # WebView Interface
            if not webview_interface_found and re.search(WEBVIEW_INTERFACE_PATTERN, dex_data):
                webview_interface_found = True
                findings.append(create_finding(
                    "WebView JavaScript Interface Detected",
                    "Critical",
                    "M1: Improper Platform Usage",
                    "addJavascriptInterface may allow code execution via WebView.",
                    "Remove or properly secure JavaScript interfaces."
                ))

            # WebView HTTP Load
            if not webview_http_found and re.search(WEBVIEW_HTTP_PATTERN, dex_data):
                webview_http_found = True
                findings.append(create_finding(
                    "WebView Loads HTTP Content",
                    "High",
                    "M3: Insecure Communication",
                    "WebView loads content over HTTP.",
                    "Use HTTPS to prevent man-in-the-middle attacks."
                ))

            # Hardcoded HTTP URLs
            if not http_found and re.search(HTTP_URL_PATTERN, dex_data):
                http_found = True
                findings.append(create_finding(
                    "Hardcoded HTTP endpoint detected",
                    "High",
                    "M3: Insecure Communication",
                    "Application contains hardcoded HTTP URL.",
                    "Use HTTPS and avoid embedding sensitive endpoints."
                ))

            # Raw IP Address
            if not ip_found and re.search(IP_ADDRESS_PATTERN, dex_data):
                ip_found = True
                findings.append(create_finding(
                    "Hardcoded IP address detected",
                    "Medium",
                    "M3: Insecure Communication",
                    "Application contains raw IP address reference.",
                    "Avoid embedding raw IP addresses inside application."
                ))

            # Firebase Detection
            if not firebase_found and re.search(FIREBASE_PATTERN, dex_data):
                firebase_found = True
                findings.append(create_finding(
                    "Firebase backend reference detected",
                    "Medium",
                    "M2: Insecure Data Storage",
                    "Firebase endpoint reference found in DEX file.",
                    "Ensure Firebase security rules are properly configured."
                ))

            # AWS Detection
            if not aws_found and re.search(AWS_PATTERN, dex_data):
                aws_found = True
                findings.append(create_finding(
                    "AWS S3 endpoint reference detected",
                    "Medium",
                    "M2: Insecure Data Storage",
                    "AWS S3 bucket reference found in application.",
                    "Ensure S3 buckets are private and access-controlled."
                ))

    return findings