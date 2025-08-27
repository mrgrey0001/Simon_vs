#!/usr/bin/env python3
"""
S!M0N vuln-scanner: Web vulnerability scanner with PDF reporting.
"""

import sys
import argparse
import requests
from urllib.parse import urljoin
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.GREEN}
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ {Fore.CYAN}S!M0N{Fore.GREEN} ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
{Style.RESET_ALL}
"""
    subtitle = f"{Fore.BLUE}--- Automated Web Vulnerability Scanner by GR3Y ---{Style.RESET_ALL}"
    print(banner)
    print(subtitle.center(40, "-"))
    print("\n")


class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        self.headers = {'User-Agent': 'Simon_vs/1.0'}

    def load_payloads(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            return []

    def scan(self):
        self.check_server_version_disclosure()
        self.check_clickjacking()
        self.check_directory_listing()
        self.check_internal_ip_disclosure()
        self.check_verbose_error_messages()
        self.check_open_redirect()
        self.check_insecure_cookies()
        self.check_sql_injection()
        self.check_path_traversal()
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
        }
        categorized = {'High': [], 'Medium': [], 'Low': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    # ---- LOW RISK ----
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

    # ---- MEDIUM RISK ----
    def check_open_redirect(self):
        payloads = self.load_payloads("payloads/redirect.txt")
        for p in tqdm(payloads, desc="[Open Redirect Test]", ncols=100, colour="yellow"):
            test_url = urljoin(self.target_url, p)
            try:
                resp = self.session.get(test_url, allow_redirects=False, headers=self.headers, timeout=10)
                if resp.status_code in (301, 302) and 'evil.com' in resp.headers.get('Location', ''):
                    self.vulnerabilities.append({
                        'type': 'Open Redirect',
                        'url': test_url,
                        'description': 'Open redirect detected'
                    })
            except Exception:
                continue

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

    # ---- HIGH RISK ----
    def check_sql_injection(self):
        payloads = self.load_payloads("payloads/sqli.txt")
        for p in tqdm(payloads, desc="[SQLi Test]", ncols=100, colour="red"):
            test_url = urljoin(self.target_url, f"/search?query={p}")
            try:
                resp = self.session.get(test_url, headers=self.headers, timeout=10)
                if any(err in resp.text.lower() for err in ["syntax error", "mysql", "sql", "odbc"]):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': test_url,
                        'description': f'Potential SQL injection with payload: {p}'
                    })
            except Exception:
                continue

    def check_path_traversal(self):
        payloads = self.load_payloads("payloads/traversal.txt")
        for p in tqdm(payloads, desc="[Path Traversal Test]", ncols=100, colour="red"):
            test_url = urljoin(self.target_url, p)
            try:
                resp = self.session.get(test_url, headers=self.headers, timeout=10)
                if "root:" in resp.text:
                    self.vulnerabilities.append({
                        'type': 'Path Traversal',
                        'url': test_url,
                        'description': f'Potential path traversal vulnerability with payload: {p}'
                    })
            except Exception:
                continue


def generate_report(filename, findings):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    heading = styles['Heading2']
    heading.alignment = TA_CENTER
    elements = []
    elements.append(Paragraph("Vulnerability Assessment Report", styles['Title']))
    elements.append(Spacer(1, 12))
    for severity in ['High', 'Medium', 'Low']:
        if findings[severity]:
            elements.append(Paragraph(f"{severity} Risk Findings", heading))
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
    parser.add_argument('-o', '--output', default="vulnerability_report.pdf", help='Output PDF filename')
    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.domain)
    findings = scanner.scan()
    generate_report(args.output, findings)
    print(f"\n{Fore.GREEN}[+] Scan complete. Report saved as {args.output}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
