#!/usr/bin/env python3
"""
S!M0N vuln-scanner v2: Enhanced Web vulnerability scanner with PDF reporting.
"""

import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from colorama import Fore, Style, init
from tqdm import tqdm
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.GREEN}
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ {Fore.CYAN}G R 3 Y{Fore.GREEN} ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
{Style.RESET_ALL}
"""
    subtitle = f"{Fore.BLUE}--- Enhanced Automated Web Vulnerability Scanner v2.0 by GR3Y ---{Style.RESET_ALL}"
    print(banner)
    print(subtitle.center(50, "-"))
    print("\n")


class EnhancedVulnerabilityScanner:
    def __init__(self, target_url, max_threads=5):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.discovered_urls = set()
        self.max_threads = max_threads
        self.forms = []

    def load_payloads(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            return []

    def crawl_site(self, max_depth=2):
        """Crawl the website to discover URLs and forms"""
        print(f"{Fore.CYAN}[*] Crawling website to discover endpoints...{Style.RESET_ALL}")
        to_visit = [(self.target_url, 0)]
        visited = set()
        
        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            
            try:
                resp = self.session.get(url, headers=self.headers, timeout=10)
                self.discovered_urls.add(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Extract forms
                for form in soup.find_all('form'):
                    self.forms.append({
                        'url': url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').lower(),
                        'inputs': [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                    })
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if urlparse(next_url).netloc == urlparse(self.target_url).netloc:
                        if next_url not in visited:
                            to_visit.append((next_url, depth + 1))
            except Exception:
                continue
        
        print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_urls)} URLs and {len(self.forms)} forms{Style.RESET_ALL}")

    def scan(self):
        print(f"{Fore.YELLOW}[*] Starting comprehensive vulnerability scan...{Style.RESET_ALL}\n")
        
        # Crawl first
        self.crawl_site()
        
        # Information gathering
        self.check_server_version_disclosure()
        self.check_technology_detection()
        self.check_security_headers()
        
        # Low risk checks
        self.check_clickjacking()
        self.check_directory_listing()
        self.check_internal_ip_disclosure()
        self.check_verbose_error_messages()
        self.check_cors_misconfiguration()
        
        # Medium risk checks
        self.check_open_redirect()
        self.check_insecure_cookies()
        self.check_missing_security_headers()
        self.check_http_methods()
        
        # High risk checks
        self.check_sql_injection()
        self.check_xss()
        self.check_path_traversal()
        self.check_command_injection()
        self.check_xxe()
        
        return self.categorize_vulnerabilities()

    def categorize_vulnerabilities(self):
        severity_map = {
            'Server Version Disclosure': 'Low',
            'Technology Detection': 'Info',
            'Security Headers Missing': 'Low',
            'Clickjacking': 'Low',
            'Directory Listing': 'Low',
            'Internal IP Disclosure': 'Low',
            'Verbose Error Messages': 'Low',
            'CORS Misconfiguration': 'Medium',
            'Open Redirect': 'Medium',
            'Insecure Cookies': 'Medium',
            'Dangerous HTTP Methods': 'Medium',
            'SQL Injection': 'Critical',
            'Cross-Site Scripting (XSS)': 'Critical',
            'Path Traversal': 'Critical',
            'Command Injection': 'Critical',
            'XXE Injection': 'Critical',
        }
        categorized = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    # ---- INFORMATION GATHERING ----
    def check_technology_detection(self):
        """Detect technologies used by the target"""
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            tech_stack = []
            
            # Check headers for technologies
            if 'X-Powered-By' in resp.headers:
                tech_stack.append(resp.headers['X-Powered-By'])
            
            # Check HTML for common patterns
            patterns = {
                'WordPress': r'wp-content|wp-includes',
                'Joomla': r'com_content|Joomla',
                'Drupal': r'Drupal\.settings|drupal\.js',
                'Laravel': r'laravel_session',
                'React': r'react',
                'Vue': r'vue',
                'Angular': r'ng-version'
            }
            
            for tech, pattern in patterns.items():
                if re.search(pattern, resp.text, re.IGNORECASE):
                    tech_stack.append(tech)
            
            if tech_stack:
                self.vulnerabilities.append({
                    'type': 'Technology Detection',
                    'url': self.target_url,
                    'description': f'Detected technologies: {", ".join(set(tech_stack))}'
                })
        except Exception:
            pass

    def check_security_headers(self):
        """Check for security-related headers"""
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            missing = [h for h in security_headers if h.lower() not in [k.lower() for k in resp.headers.keys()]]
            
            if missing:
                self.vulnerabilities.append({
                    'type': 'Security Headers Missing',
                    'url': self.target_url,
                    'description': f'Missing security headers: {", ".join(missing)}'
                })
        except Exception:
            pass

    # ---- EXISTING CHECKS (Enhanced) ----
    def check_server_version_disclosure(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            server = resp.headers.get('Server')
            x_powered = resp.headers.get('X-Powered-By')
            
            if server:
                self.vulnerabilities.append({
                    'type': 'Server Version Disclosure',
                    'url': self.target_url,
                    'description': f'Server header reveals: {server}'
                })
            if x_powered:
                self.vulnerabilities.append({
                    'type': 'Server Version Disclosure',
                    'url': self.target_url,
                    'description': f'X-Powered-By header reveals: {x_powered}'
                })
        except Exception:
            pass

    def check_clickjacking(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            has_xframe = 'x-frame-options' in [h.lower() for h in resp.headers.keys()]
            has_csp_frame = 'content-security-policy' in [h.lower() for h in resp.headers.keys()]
            
            if not has_xframe and not has_csp_frame:
                self.vulnerabilities.append({
                    'type': 'Clickjacking',
                    'url': self.target_url,
                    'description': 'No X-Frame-Options or CSP frame-ancestors directive set'
                })
        except Exception:
            pass

    def check_cors_misconfiguration(self):
        """Check for CORS misconfigurations"""
        try:
            test_origins = ['https://evil.com', 'null']
            for origin in test_origins:
                headers = self.headers.copy()
                headers['Origin'] = origin
                resp = self.session.get(self.target_url, headers=headers, timeout=10)
                
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    if acac.lower() == 'true':
                        self.vulnerabilities.append({
                            'type': 'CORS Misconfiguration',
                            'url': self.target_url,
                            'description': f'CORS allows credentials from arbitrary origin: {origin}'
                        })
        except Exception:
            pass

    def check_http_methods(self):
        """Check for dangerous HTTP methods"""
        try:
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            for method in dangerous_methods:
                resp = self.session.request(method, self.target_url, headers=self.headers, timeout=10)
                if resp.status_code not in [405, 501]:
                    self.vulnerabilities.append({
                        'type': 'Dangerous HTTP Methods',
                        'url': self.target_url,
                        'description': f'HTTP method {method} is allowed (status: {resp.status_code})'
                    })
        except Exception:
            pass

    # ---- NEW HIGH-RISK CHECKS ----
    def check_xss(self):
        """Check for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>'
        ]
        
        if not self.forms:
            xss_payloads_short = xss_payloads[:2]  # Use fewer if no forms found
        else:
            xss_payloads_short = xss_payloads
        
        # Test URL parameters
        for url in list(self.discovered_urls)[:10]:  # Limit to first 10 URLs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in xss_payloads_short:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    try:
                        resp = self.session.get(test_url, headers=self.headers, timeout=10)
                        if payload in resp.text:
                            self.vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'url': test_url,
                                'description': f'Reflected XSS found in parameter: {param}'
                            })
                            break  # Found vulnerability, move to next param
                    except Exception:
                        continue

    def check_command_injection(self):
        """Check for command injection vulnerabilities"""
        cmd_payloads = [
            '; ls',
            '| whoami',
            '`id`',
            '$(whoami)'
        ]
        
        for url in list(self.discovered_urls)[:5]:  # Test first 5 URLs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in cmd_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    try:
                        resp = self.session.get(test_url, headers=self.headers, timeout=10)
                        # Look for command execution indicators
                        if any(indicator in resp.text.lower() for indicator in ['uid=', 'gid=', 'root:', 'www-data']):
                            self.vulnerabilities.append({
                                'type': 'Command Injection',
                                'url': test_url,
                                'description': f'Potential command injection in parameter: {param}'
                            })
                            break
                    except Exception:
                        continue

    def check_xxe(self):
        """Check for XXE (XML External Entity) vulnerabilities"""
        xxe_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''
        
        for url in list(self.discovered_urls)[:5]:
            try:
                headers = self.headers.copy()
                headers['Content-Type'] = 'application/xml'
                resp = self.session.post(url, data=xxe_payload, headers=headers, timeout=10)
                
                if 'root:' in resp.text:
                    self.vulnerabilities.append({
                        'type': 'XXE Injection',
                        'url': url,
                        'description': 'XXE vulnerability detected - XML parser processes external entities'
                    })
            except Exception:
                continue

    # ---- ENHANCED EXISTING CHECKS ----
    def check_directory_listing(self):
        common_dirs = ['/', '/uploads/', '/images/', '/files/', '/backup/', '/admin/']
        for dir_path in common_dirs:
            try:
                test_url = self.target_url + dir_path
                resp = self.session.get(test_url, headers=self.headers, timeout=10)
                if any(indicator in resp.text for indicator in ["Index of", "Directory listing", "Parent Directory"]):
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'url': test_url,
                        'description': f'Directory listing enabled at: {dir_path}'
                    })
            except Exception:
                continue

    def check_internal_ip_disclosure(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            ip_pattern = r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b'
            matches = re.findall(ip_pattern, resp.text)
            
            if matches:
                self.vulnerabilities.append({
                    'type': 'Internal IP Disclosure',
                    'url': self.target_url,
                    'description': f'Internal IP addresses found: {", ".join(set(matches))}'
                })
        except Exception:
            pass

    def check_verbose_error_messages(self):
        test_paths = ['/thispagedoesnotexist', '/%00', '/..%2f..%2f']
        for path in test_paths:
            try:
                resp = self.session.get(self.target_url + path, headers=self.headers, timeout=10)
                error_indicators = ['exception', 'traceback', 'stack trace', 'error on line', 
                                  'mysqli', 'postgresql', 'odbc', 'warning:', 'fatal error']
                
                if any(err in resp.text.lower() for err in error_indicators):
                    self.vulnerabilities.append({
                        'type': 'Verbose Error Messages',
                        'url': self.target_url + path,
                        'description': 'Verbose error message or stack trace exposed'
                    })
                    break
            except Exception:
                continue

    def check_open_redirect(self):
        redirect_payloads = [
            '?url=https://evil.com',
            '?redirect=//evil.com',
            '?next=https://evil.com',
            '?return=//evil.com'
        ]
        
        for payload in tqdm(redirect_payloads, desc="[Open Redirect]", ncols=100, colour="yellow"):
            test_url = self.target_url + payload
            try:
                resp = self.session.get(test_url, allow_redirects=False, headers=self.headers, timeout=10)
                location = resp.headers.get('Location', '')
                
                if resp.status_code in (301, 302, 303, 307, 308):
                    if 'evil.com' in location or location.startswith('//evil.com'):
                        self.vulnerabilities.append({
                            'type': 'Open Redirect',
                            'url': test_url,
                            'description': f'Open redirect to: {location}'
                        })
            except Exception:
                continue

    def check_insecure_cookies(self):
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite attribute')
                
                if issues:
                    self.vulnerabilities.append({
                        'type': 'Insecure Cookies',
                        'url': self.target_url,
                        'description': f'Cookie "{cookie.name}": {", ".join(issues)}'
                    })
        except Exception:
            pass

    def check_missing_security_headers(self):
        """Detailed check for missing security headers"""
        try:
            resp = self.session.get(self.target_url, headers=self.headers, timeout=10)
            
            # Check HSTS
            if 'strict-transport-security' not in [h.lower() for h in resp.headers.keys()]:
                self.vulnerabilities.append({
                    'type': 'Security Headers Missing',
                    'url': self.target_url,
                    'description': 'Missing Strict-Transport-Security (HSTS) header'
                })
            
            # Check CSP
            if 'content-security-policy' not in [h.lower() for h in resp.headers.keys()]:
                self.vulnerabilities.append({
                    'type': 'Security Headers Missing',
                    'url': self.target_url,
                    'description': 'Missing Content-Security-Policy header'
                })
        except Exception:
            pass

    def check_sql_injection(self):
        sqli_payloads = ["'", "1' OR '1'='1", "1' AND '1'='2", "' OR 1=1--", "1' UNION SELECT NULL--"]
        
        # Test URL parameters
        for url in tqdm(list(self.discovered_urls)[:10], desc="[SQL Injection]", ncols=100, colour="red"):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in sqli_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    try:
                        resp = self.session.get(test_url, headers=self.headers, timeout=10)
                        sql_errors = ['syntax error', 'mysql', 'mysqli', 'postgresql', 'odbc', 
                                    'sql syntax', 'sqlite', 'oracle', 'mssql', 'unclosed quotation']
                        
                        if any(err in resp.text.lower() for err in sql_errors):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'url': test_url,
                                'description': f'SQL injection vulnerability in parameter: {param}'
                            })
                            break
                    except Exception:
                        continue

    def check_path_traversal(self):
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd'
        ]
        
        for payload in tqdm(traversal_payloads, desc="[Path Traversal]", ncols=100, colour="red"):
            # Test in various contexts
            test_urls = [
                f"{self.target_url}?file={payload}",
                f"{self.target_url}?path={payload}",
                f"{self.target_url}/{payload}"
            ]
            
            for test_url in test_urls:
                try:
                    resp = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    # Check for Unix/Linux indicators
                    if re.search(r'root:.*:0:0:', resp.text):
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'url': test_url,
                            'description': 'Path traversal vulnerability - accessed /etc/passwd'
                        })
                        break
                    
                    # Check for Windows indicators
                    if '[extensions]' in resp.text.lower() or '[fonts]' in resp.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'url': test_url,
                            'description': 'Path traversal vulnerability - accessed win.ini'
                        })
                        break
                except Exception:
                    continue


def generate_report(filename, findings, target_url):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    heading = styles['Heading2']
    heading.alignment = TA_CENTER
    elements = []
    
    # Title
    elements.append(Paragraph("Security Vulnerability Assessment Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Target:</b> {target_url}", styles['BodyText']))
    elements.append(Paragraph(f"<b>Scan Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyText']))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    total_vulns = sum(len(v) for v in findings.values())
    elements.append(Paragraph("Executive Summary", heading))
    elements.append(Paragraph(f"Total vulnerabilities found: <b>{total_vulns}</b>", styles['BodyText']))
    
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count = len(findings.get(severity, []))
        if count > 0:
            elements.append(Paragraph(f"{severity}: {count}", styles['BodyText']))
    
    elements.append(Spacer(1, 20))
    
    # Detailed Findings
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if findings.get(severity):
            elements.append(Paragraph(f"{severity} Risk Findings", heading))
            elements.append(Spacer(1, 12))
            
            for vuln in findings[severity]:
                elements.append(Paragraph(f"<b>Type:</b> {vuln['type']}", styles['Heading3']))
                elements.append(Paragraph(f"<b>URL:</b> {vuln['url']}", styles['BodyText']))
                elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles['BodyText']))
                elements.append(Spacer(1, 12))
    
    if not any(findings.values()):
        elements.append(Paragraph("No vulnerabilities found.", styles['BodyText']))
    
    doc.build(elements)


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="S!M0N vuln-scanner v2: Enhanced web vulnerability scanner with PDF reporting."
    )
    parser.add_argument('-d', '--domain', required=True, help='Target website URL (e.g., http://example.com)')
    parser.add_argument('-o', '--output', default="vulnerability_report.pdf", help='Output PDF filename')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--no-crawl', action='store_true', help='Skip website crawling')
    args = parser.parse_args()

    print(f"{Fore.CYAN}[*] Target: {args.domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Output: {args.output}{Style.RESET_ALL}\n")
    
    scanner = EnhancedVulnerabilityScanner(args.domain, max_threads=args.threads)
    findings = scanner.scan()
    
    # Final summary display in terminal
    total = sum(len(v) for v in findings.values())
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Scan Complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Total Vulnerabilities Found: {total}{Style.RESET_ALL}")
    
    for severity, vulns in findings.items():
        if vulns:
            color = Fore.RED if severity in ['Critical', 'High'] else Fore.YELLOW if severity == 'Medium' else Fore.BLUE
            print(f"{color}- {severity}: {len(vulns)}{Style.RESET_ALL}")

    # Generate the PDF report
    try:
        print(f"\n{Fore.CYAN}[*] Generating PDF report: {args.output}...{Style.RESET_ALL}")
        generate_report(args.output, findings, args.domain)
        print(f"{Fore.GREEN}[+] Report saved successfully!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to generate report: {e}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)
