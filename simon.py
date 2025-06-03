#!/usr/bin/env python3
"""
S!M0N vuln-scanner: Web vulnerability scanner with PDF reporting.
"""

import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

def print_banner():
    main_banner = r"""
     _____  __  __   ___  __  __ 
    / ____||  \/  | / _ \|  \/  |
   | (___  | \  / || | | | \  / |
    \___ \ | |\/| || | | | |\/| |
    ____) || |  | || |_| | |  | |
   |_____/ |_|  |_| \___/|_|  |_|
    """
    subtitle = "vuln-scanner"
    print(main_banner)
    print(subtitle.center(40, "-"))
    print("\n")

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        self.headers = {'User-Agent': 'Simon_vs/1.0'}

    def scan(self):
        self.check_server_version_disclosure()
        self.check_clickjacking()
        self.check_directory_listing()
        self.check_internal_ip_disclosure()
        self.check_verbose_error_messages()
        self.check_open_redirect()
        self.check_insecure_cookies()
        # ... Add all other checks here
        self.check_sql_injection()
        self.check_path_traversal()
        # ... Add more as needed
        return self.categorize_vulnerabilities()

    def categorize_vulnerabilities(self):
        severity_map = {
            'Server Version Disclosure': 'Low',
            'Clickjacking': 'Low',
            'Directory Listing': 'Low',
            'Internal IP Disclosure': 'Low',
            'Verbose Error Messages': 'Low',
            'Open Redirect': 'Medium',
            'Insecure Cookies': 'Medium',
            'SQL Injection': 'High',
            'Path Traversal': 'High',
            # ... Add all others
        }
        categorized = {'High': [], 'Medium': [], 'Low': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    # ---- LOW RISK CHECKS ----
    def check_server_version_disclosure(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            server = resp.headers.get('Server')
            if server:
                self.vulnerabilities.append({
                    'type': 'Server Version Disclosure',
                    'url': self.target_url,
                    'description': f'Server header present: {server}'
                })
        except Exception:
            pass

    def check_clickjacking(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            if 'x-frame-options' not in resp.headers and 'content-security-policy' not in resp.headers:
                self.vulnerabilities.append({
                    'type': 'Clickjacking',
                    'url': self.target_url,
                    'description': 'No X-Frame-Options or CSP frame policy set'
                })
        except Exception:
            pass

    def check_directory_listing(self):
        try:
            resp = self.session.get(self.target_url + '/', headers=self.headers, timeout=10)
            if "Index of /" in resp.text:
                self.vulnerabilities.append({
                    'type': 'Directory Listing',
                    'url': self.target_url,
                    'description': 'Directory listing is enabled'
                })
        except Exception:
            pass

    def check_internal_ip_disclosure(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            if any(ip in resp.text for ip in ['192.168.', '10.', '172.16.']):
                self.vulnerabilities.append({
                    'type': 'Internal IP Disclosure',
                    'url': self.target_url,
                    'description': 'Internal IP address found in response'
                })
        except Exception:
            pass

    def check_verbose_error_messages(self):
        try:
            resp = self.session.get(self.target_url + "/thispagedoesnotexist", headers=self.headers, timeout=10)
            if any(err in resp.text.lower() for err in ['exception', 'traceback', 'stack trace', 'error on line']):
                self.vulnerabilities.append({
                    'type': 'Verbose Error Messages',
                    'url': self.target_url,
                    'description': 'Verbose error message or stack trace found'
                })
        except Exception:
            pass

    # ---- MEDIUM RISK CHECKS ----
    def check_open_redirect(self):
        test_url = urljoin(self.target_url, "/redirect?url=https://evil.com")
        try:
            resp = self.session.get(test_url, allow_redirects=False, headers=self.headers, timeout=10)
            if resp.status_code in (301, 302) and 'evil.com' in resp.headers.get('Location', ''):
                self.vulnerabilities.append({
                    'type': 'Open Redirect',
                    'url': test_url,
                    'description': 'Open redirect detected'
                })
        except Exception:
            pass

    def check_insecure_cookies(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            for cookie in resp.cookies:
                if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                    self.vulnerabilities.append({
                        'type': 'Insecure Cookies',
                        'url': self.target_url,
                        'description': f'Cookie {cookie.name} missing Secure/HttpOnly'
                    })
        except Exception:
            pass

    # ---- HIGH RISK CHECKS ----
    def check_sql_injection(self):
        test_url = urljoin(self.target_url, "/search?query='OR%201=1--")
        try:
            resp = self.session.get(test_url, headers=self.headers, timeout=10)
            if "syntax error" in resp.text.lower() or "mysql" in resp.text.lower():
                self.vulnerabilities.append({
                    'type': 'SQL Injection',
                    'url': test_url,
                    'description': 'Potential SQL injection vulnerability'
                })
        except Exception:
            pass

    def check_path_traversal(self):
        test_url = urljoin(self.target_url, "/../../../../etc/passwd")
        try:
            resp = self.session.get(test_url, headers=self.headers, timeout=10)
            if "root:" in resp.text:
                self.vulnerabilities.append({
                    'type': 'Path Traversal',
                    'url': test_url,
                    'description': 'Potential path traversal vulnerability'
                })
        except Exception:
            pass

    # Add more checks as needed...

def generate_report(filename, findings):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    # FIX: Use ParagraphStyle, not Paragraph, for custom styles
    styles.add(ParagraphStyle(name='SeverityHeading', parent=styles['Heading2'], alignment=TA_CENTER))
    elements = []
    elements.append(Paragraph("Bug Report By S!M0N", styles['Title']))
    elements.append(Spacer(1, 12))
    for severity in ['High', 'Medium', 'Low']:
        if findings[severity]:
            elements.append(Paragraph(f"{severity} Risk Findings", styles['SeverityHeading']))
            elements.append(Spacer(1, 8))
            for vuln in findings[severity]:
                elements.append(Paragraph(f"<b>Type:</b> {vuln['type']}", styles['Heading3']))
                elements.append(Paragraph(f"<b>URL:</b> {vuln['url']}", styles['BodyText']))
                elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles['BodyText']))
                elements.append(Spacer(1, 8))
    if not any(findings.values()):
        elements.append(Paragraph("No vulnerabilities found.", styles['BodyText']))
    doc.build(elements)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="S!M0N vuln-scanner: Web vulnerability scanner with PDF reporting.")
    parser.add_argument('-d', '--domain', required=True, help='Target website URL (e.g., http://example.com)')
    args = parser.parse_args()
    target = args.domain
    scanner = VulnerabilityScanner(target)
    findings = scanner.scan()
    report_file = "vulnerability_report.pdf"
    generate_report(report_file, findings)
    print(f"[+] Scan complete. Report generated: {report_file}")

if __name__ == "__main__":
    main()
