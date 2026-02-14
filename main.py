import logging
logging.basicConfig(level=logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)
import sys
from analyzer import analyze_apk
from report_generator import generate_report

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <apk_file>")
        sys.exit(1)

    apk_path = sys.argv[1]

    findings = analyze_apk(apk_path)
    print(f"[+] {len(findings)} issues found.")

    generate_report(findings)

if __name__ == "__main__":
    main()