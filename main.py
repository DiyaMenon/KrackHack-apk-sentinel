import logging
import sys
from analyzer import analyze_apk
from report_generator import generate_report

# Suppress noisy logs for the CI/CD pipeline
logging.basicConfig(level=logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <apk_file>")
        sys.exit(1)

    apk_path = sys.argv[1]

    print(f"🚀 [CI/CD] Initiating APK Sentinel Scan on: {apk_path}...")
    findings, metadata = analyze_apk(apk_path)
    
    print(f"📊 [CI/CD] Scan complete. Generating compliance reports...")
    generate_report(findings, metadata)

    # --- THE DEVSECOPS BLOCKER LOGIC ---
    critical_issues = [f for f in findings if f['severity'] == 'Critical']
    
    if len(critical_issues) > 0:
        print("\n" + "="*50)
        print(f"PIPELINE FAILED: {len(critical_issues)} CRITICAL VULNERABILITIES DETECTED!")
        print("="*50)
        for issue in critical_issues:
            print(f"- {issue['title']}")
        print("\nAction Required: You must fix these issues before merging this Pull Request.")
        
        # sys.exit(1) tells GitHub Actions to trigger a massive RED X and block the code
        sys.exit(1) 
    else:
        print("\nPIPELINE PASSED: No critical vulnerabilities detected. Safe to merge.")
        sys.exit(0)

if __name__ == "__main__":
    main()