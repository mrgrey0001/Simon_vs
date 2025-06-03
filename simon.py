import sys
import argparse
import requests
import random
from urllib.parse import urljoin, urlencode
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
]

COMMON_PARAMS = ["id", "page", "search", "q", "query", "item", "cat"]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR sleep(5)--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>"
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini"
]

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
    print(Fore.GREEN + main_banner)
    print(Fore.YELLOW + subtitle.center(40, "-"))
    print("\n")

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []

    def scan(self):
        print(Fore.CYAN + "[*] Starting vulnerability scan...\n")
        self.check_sql_injection()
        self.check_xss()
        self.check_path_traversal()
        self.check_clickjacking()
        print(Fore.CYAN + "\n[*] Scan complete.\n")
        return self.categorize_vulnerabilities()

    def categorize_vulnerabilities(self):
        severity_map = {
            'SQL Injection': 'High',
            'XSS': 'High',
            'Path Traversal': 'High',
            'Clickjacking': 'Low'
        }
        categorized = {'High': [], 'Medium': [], 'Low': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    def send_request(self, url, params=None):
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=10)
            return resp
        except Exception:
            return None

    def check_sql_injection(self):
        print(Fore.MAGENTA + "[*] Checking for SQL Injection...")
        for param in tqdm(COMMON_PARAMS, desc="SQLi"):
            for payload in SQLI_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp and ("syntax error" in resp.text.lower() or "mysql" in resp.text.lower() or "you have an error in your sql syntax" in resp.text.lower()):
                    print(Fore.RED + f"[!] SQL Injection detected with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': resp.url,
                        'description': f"Possible SQLi with param '{param}' and payload '{payload}'"
                    })

    def check_xss(self):
        print(Fore.MAGENTA + "[*] Checking for XSS...")
        for param in tqdm(COMMON_PARAMS, desc="XSS"):
            for payload in XSS_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp and payload in resp.text:
                    print(Fore.RED + f"[!] XSS detected with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': resp.url,
                        'description': f"Possible XSS with param '{param}' and payload '{payload}'"
                    })

    def check_path_traversal(self):
        print(Fore.MAGENTA + "[*] Checking for Path Traversal...")
        for param in tqdm(COMMON_PARAMS, desc="Traversal"):
            for payload in PATH_TRAVERSAL_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp and ("root:x" in resp.text or "[extensions]" in resp.text):
                    print(Fore.RED + f"[!] Path Traversal detected with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'Path Traversal',
                        'url': resp.url,
                        'description': f"Possible Path Traversal with param '{param}' and payload '{payload}'"
                    })

    def check_clickjacking(self):
        print(Fore.MAGENTA + "[*] Checking for Clickjacking...")
        resp = self.send_request(self.target_url)
        if resp and 'x-frame-options' not in resp.headers and 'content-security-policy' not in resp.headers:
            print(Fore.YELLOW + "[!] Clickjacking risk: No X-Frame-Options or CSP frame policy set")
            self.vulnerabilities.append({
                'type': 'Clickjacking',
                'url': self.target_url,
                'description': 'No X-Frame-Options or CSP frame policy set'
            })

def generate_report(filename, findings):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
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
    print(Fore.GREEN + f"[+] Scan complete. Report generated: {report_file}")

if __name__ == "__main__":
    main()
