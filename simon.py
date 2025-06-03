import sys
import argparse
import requests
import random
from urllib.parse import urljoin, urlparse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from tqdm import tqdm
from colorama import Fore, Style, init
from bs4 import BeautifulSoup

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
░▒▓███████▓▒░ ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░         ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
    """
    subtitle = "SiM0N vuln-scanner"
    print(Fore.GREEN + main_banner)
    print(Fore.RED + subtitle.center(80, "-"))
    print("\n")

def crawl_urls(base_url, max_depth):
    visited = set()
    to_visit = [(base_url, 0)]
    found_urls = set([base_url])
    while to_visit:
        url, depth = to_visit.pop(0)
        if depth >= max_depth or url in visited:
            continue
        visited.add(url)
        try:
            resp = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                abs_url = urljoin(url, link['href'])
                # Only crawl within the same domain
                if urlparse(abs_url).netloc == urlparse(base_url).netloc and abs_url not in found_urls:
                    found_urls.add(abs_url)
                    to_visit.append((abs_url, depth + 1))
        except Exception:
            continue
    return list(found_urls)

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []

    def scan(self):
        self.check_sql_injection()
        self.check_xss()
        self.check_path_traversal()
        self.check_clickjacking()
        self.check_open_redirect()
        self.check_sensitive_files()
        return self.categorize_vulnerabilities()

    def categorize_vulnerabilities(self):
        severity_map = {
            'SQL Injection': 'High',
            'XSS': 'High',
            'Path Traversal': 'High',
            'Clickjacking': 'Low',
            'Open Redirect': 'Medium',
            'Sensitive File/Directory': 'Medium'
        }
        categorized = {'High': [], 'Medium': [], 'Low': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    def send_request(self, url, params=None):
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=10, allow_redirects=True)
            return resp
        except Exception:
            return None

    def check_sql_injection(self):
        for param in COMMON_PARAMS:
            for payload in SQLI_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp and ("syntax error" in resp.text.lower() or "mysql" in resp.text.lower() or "you have an error in your sql syntax" in resp.text.lower()):
                    print(Fore.RED + f"[!] SQL Injection detected at {resp.url} with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': resp.url,
                        'description': f"Possible SQLi with param '{param}' and payload '{payload}'"
                    })

    def check_xss(self):
        for param in COMMON_PARAMS:
            for payload in XSS_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp and payload in resp.text:
                    print(Fore.RED + f"[!] XSS detected at {resp.url} with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': resp.url,
                        'description': f"Possible XSS with param '{param}' and payload '{payload}'"
                    })

    def check_path_traversal(self):
        for param in COMMON_PARAMS:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp and ("root:x" in resp.text or "[extensions]" in resp.text):
                    print(Fore.RED + f"[!] Path Traversal detected at {resp.url} with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'Path Traversal',
                        'url': resp.url,
                        'description': f"Possible Path Traversal with param '{param}' and payload '{payload}'"
                    })

    def check_clickjacking(self):
        resp = self.send_request(self.target_url)
        if resp and 'x-frame-options' not in resp.headers and 'content-security-policy' not in resp.headers:
            print(Fore.YELLOW + f"[!] Clickjacking risk at {self.target_url}: No X-Frame-Options or CSP frame policy set")
            self.vulnerabilities.append({
                'type': 'Clickjacking',
                'url': self.target_url,
                'description': 'No X-Frame-Options or CSP frame policy set'
            })

    def check_open_redirect(self):
        payload = "//evil.com"
        for param in COMMON_PARAMS:
            params = {param: payload}
            resp = self.send_request(self.target_url, params)
            if resp and (payload in resp.url or resp.is_redirect):
                print(Fore.YELLOW + f"[!] Open Redirect detected at {resp.url} with param '{param}'")
                self.vulnerabilities.append({
                    'type': 'Open Redirect',
                    'url': resp.url,
                    'description': f"Possible open redirect with param '{param}'"
                })

    def check_sensitive_files(self):
        sensitive_paths = ["/robots.txt", "/.env", "/admin", "/backup.zip", "/.git", "/.htaccess", "/config.php"]
        for path in sensitive_paths:
            url = urljoin(self.target_url, path)
            resp = self.send_request(url)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                print(Fore.YELLOW + f"[!] Sensitive file or directory found: {url}")
                self.vulnerabilities.append({
                    'type': 'Sensitive File/Directory',
                    'url': url,
                    'description': f"Accessible sensitive file or directory: {path}"
                })

def generate_report(filename, findings):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SeverityHeading', parent=styles['Heading2'], alignment=TA_CENTER))
    elements = []
    elements.append(Paragraph("Bug Report By SiM0N", styles['Title']))
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
    parser = argparse.ArgumentParser(description="SiM0N vuln-scanner: Web vulnerability scanner with PDF reporting.")
    parser.add_argument('-d', '--domain', required=True, help='Target website URL (e.g., http://example.com)')
    parser.add_argument('-l', '--level', type=int, default=1, help='Crawl depth level (default: 1)')
    parser.add_argument('-o', '--output', default="vulnerability_report.pdf", help='Output PDF file name')
    args = parser.parse_args()
    target = args.domain
    level = args.level
    output_file = args.output

    print(Fore.CYAN + f"[*] Crawling up to level {level} ...")
    urls = crawl_urls(target, level)
    print(Fore.CYAN + f"[*] Found {len(urls)} URLs to scan.")

    all_findings = {'High': [], 'Medium': [], 'Low': []}
    for url in tqdm(urls, desc="Scanning URLs"):
        scanner = VulnerabilityScanner(url)
        findings = scanner.scan()
        for severity in all_findings:
            all_findings[severity].extend(findings[severity])

    generate_report(output_file, all_findings)
    print(Fore.GREEN + f"[+] Scan complete. Report generated: {output_file}")

if __name__ == "__main__":
    main()
