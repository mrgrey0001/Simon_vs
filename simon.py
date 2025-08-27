#!/usr/bin/env python3
"""
Usage:
python3 simon.py -d https://target.tld [-o report.pdf] [--timeout 10] [--threads 8] [--payload-dir payloads]
"""

import sys
import argparse
import concurrent.futures as futures
import random
import re
import time
import datetime as dt
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl

import requests
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors

BANNER = r"""
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓██████████████▓▒░  ░▒▓████████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░ G R 3 Y ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
"""

def print_banner():
    print(BANNER)
    print("vuln scanner by GR3Y".center(40, "-"))
    print()

# --------------------------- utilities ---------------------------

def load_lines(path, default_list):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except Exception:
        return list(default_list)

def uniq(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def now_iso():
    return dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

# --------------------------- scanner -----------------------------

class VulnerabilityScanner:
    def __init__(self, target_url, timeout=10, threads=8, payload_dir="payloads"):
        self.target = target_url.rstrip("/")
        self.timeout = timeout
        self.threads = max(1, threads)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Simon_vs/2.0 (+authorized-testing)'} )
        self.vulns = []

        # payloads
        self.payload_dir = payload_dir
        self.traversal_prefixes = load_lines(f"{payload_dir}/traversal_prefixes.txt",
                                             ["../../../../", "..\\..\\..\\..\\"])
        self.traversal_targets = load_lines(f"{payload_dir}/traversal_targets.txt",
                                            ["/etc/passwd", "/proc/self/environ", "windows/win.ini"])
        self.traversal_enc = load_lines(f"{payload_dir}/traversal_encodings.txt",
                                        ["..%2f", "..%5c", "..%252f", "..%255c"])
        self.sqli_payloads = load_lines(f"{payload_dir}/sqli_payloads.txt",
                                        ["' OR 1=1--", "\" OR \"1\"=\"1\"--", "') OR ('1'='1", "';WAITFOR DELAY '0:0:2'--"])
        self.sqli_params = load_lines(f"{payload_dir}/sqli_params.txt",
                                      ["q", "search", "id", "name"])
        self.openredir_params = load_lines(f"{payload_dir}/open_redirect_params.txt",
                                           ["url", "redirect", "next", "return", "continue", "dest"])
        self.xss_params = load_lines(f"{payload_dir}/xss_params.txt",
                                     ["q", "search", "s", "term"])
        self.probe_paths = load_lines(f"{payload_dir}/probe_paths.txt",
                                      ["", "/", "/search", "/login", "/products", "/?"])

        # compiled regex
        self._sql_error_re = re.compile(
            r"(sql syntax|warning: mysql|mysqli|postgresql|psql:|syntax error|ORA-\d{5}|SQLite|ODBC|JDBC|Unclosed quotation mark|Native Client|DB2|Fatal error)",
            re.I
        )

    def _get(self, url, **kw):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False, **kw)
        except Exception as e:
            return None

    def _append(self, vtype, url, desc, evidence=None, severity=None):
        self.vulns.append({
            "type": vtype,
            "url": url,
            "description": desc,
            "evidence": (evidence or "")[:2000],
            "severity": severity  # may be None, we'll map later
        })

    def scan(self):
        # run light, quick checks first
        self.check_server_version_disclosure()
        self.check_security_headers()
        self.check_directory_listing()
        self.check_internal_ip_disclosure()
        self.check_verbose_error_messages()
        self.check_insecure_cookies()
        self.check_robots_txt()

        # heavier checks (can run with thread pool over probe paths)
        heavy_checks = [
            self.check_open_redirect,
            self.check_sqli_error_based,
            self.check_path_traversal,
            self.check_reflected_xss_signal
        ]
        with futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(fn) for fn in heavy_checks]
            for _ in futures.as_completed(futs):
                pass

        return self.categorize()

    # --------------------- categorization ---------------------

    def categorize(self):
        severity_map = {
            'Server Version Disclosure': 'Low',
            'Clickjacking': 'Low',
            'Directory Listing': 'Low',
            'Internal IP Disclosure': 'Low',
            'Verbose Error Messages': 'Low',
            'Missing Security Headers': 'Low',
            'Robots.txt Sensitive Entries': 'Low',

            'Open Redirect': 'Medium',
            'Insecure Cookies': 'Medium',
            'Reflected Input (possible XSS)': 'Medium',

            'SQL Injection': 'High',
            'Path Traversal': 'High',
        }
        out = {"High": [], "Medium": [], "Low": []}
        for v in self.vulns:
            sev = v.get("severity") or severity_map.get(v["type"], "Low")
            out.setdefault(sev, []).append(v)
        return out

    # --------------------- checks: low ------------------------

    def check_server_version_disclosure(self):
        resp = self._get(self.target)
        if resp is None:
            return
        server = resp.headers.get("Server")
        x_powered = resp.headers.get("X-Powered-By")
        parts = []
        if server:
            parts.append(f"Server: {server}")
        if x_powered:
            parts.append(f"X-Powered-By: {x_powered}")
        if parts:
            self._append("Server Version Disclosure", self.target,
                         "Potentially sensitive version info exposed in headers.",
                         "; ".join(parts))

    def check_security_headers(self):
        resp = self._get(self.target)
        if resp is None:
            return
        missing = []
        want = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        for h in want:
            if h.lower() not in (k.lower() for k in resp.headers.keys()):
                missing.append(h)
        if missing:
            self._append("Missing Security Headers", self.target,
                         f"Missing: {', '.join(missing)}")

        # Clickjacking (no XFO and no CSP frame-ancestors)
        csp = resp.headers.get("Content-Security-Policy", "")
        if ("x-frame-options" not in {k.lower(): v for k, v in resp.headers.items()}
            and ("frame-ancestors" not in csp.lower())):
            self._append("Clickjacking", self.target,
                         "No X-Frame-Options or CSP frame-ancestors policy present")

    def check_directory_listing(self):
        # try root and a couple common folders from probe_paths
        candidates = uniq([self.target + "/", urljoin(self.target, "/assets/"), urljoin(self.target, "/uploads/")])
        for u in candidates:
            resp = self._get(u)
            if resp and resp.status_code == 200 and ("Index of /" in resp.text or "<title>Index of" in resp.text):
                self._append("Directory Listing", u, "Directory listing appears to be enabled.")

    def check_internal_ip_disclosure(self):
        resp = self._get(self.target)
        if resp is None:
            return
        # common private ranges
        if re.search(r"\b(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b", resp.text):
            self._append("Internal IP Disclosure", self.target, "Internal/loopback IP found in response body.")

    def check_verbose_error_messages(self):
        nonce = str(int(time.time())) + str(random.randint(1000,9999))
        u = urljoin(self.target, f"/thispage/definitely/not/{nonce}")
        resp = self._get(u)
        if resp is None:
            return
        body = resp.text.lower()
        if any(err in body for err in ["exception", "traceback", "stack trace", "error on line", "nullreferenceexception"]):
            self._append("Verbose Error Messages", u, "Verbose error/stack trace disclosed.")

    def check_insecure_cookies(self):
        resp = self._get(self.target)
        if resp is None:
            return
        # requests may collapse multiple Set-Cookie headers; get raw list
        set_cookie_values = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw, "headers") else None
        if not set_cookie_values:
            # fallback to combined header
            sc = resp.headers.get("Set-Cookie")
            set_cookie_values = [sc] if sc else []
        for sc in set_cookie_values:
            parts = [p.strip() for p in sc.split(";")]
            if not parts:
                continue
            nameval = parts[0]
            flags = {p.lower(): True for p in parts[1:]}
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            # SameSite should be present; if absent, warn
            if not any(p.lower().startswith("samesite") for p in parts[1:]):
                missing.append("SameSite")
            if missing:
                self._append("Insecure Cookies", self.target,
                             f"Cookie `{nameval}` missing: {', '.join(missing)}",
                             evidence=sc)

    def check_robots_txt(self):
        u = urljoin(self.target, "/robots.txt")
        resp = self._get(u)
        if resp and resp.status_code == 200:
            # flag potentially sensitive disallows
            hits = []
            for line in resp.text.splitlines():
                if line.lower().startswith("disallow:"):
                    p = line.split(":",1)[1].strip()
                    if any(x in p.lower() for x in ["admin", "backup", "private", "temp"]):
                        hits.append(p)
            if hits:
                self._append("Robots.txt Sensitive Entries", u, f"Sensitive paths disallowed: {', '.join(hits)}")

    # --------------------- checks: medium/high ------------------------

    def _paths_for_testing(self):
        # build a few candidate endpoints to attach params
        base_paths = uniq(self.probe_paths + ["/", ""])
        return [urljoin(self.target, p if p.startswith("/") else f"/{p}") for p in base_paths]

    def check_open_redirect(self):
        attacker = "https://example.org/evil"
        for base in self._paths_for_testing():
            for param in self.openredir_params:
                # preserve existing query if any
                parsed = urlparse(base)
                q = dict(parse_qsl(parsed.query))
                q[param] = attacker
                test_url = parsed._replace(query=urlencode(q, doseq=True)).geturl()
                resp = self._get(test_url)
                if not resp:
                    continue
                loc = resp.headers.get("Location", "")
                # must redirect and location host should be example.org
                if resp.status_code in (301,302,303,307,308) and "example.org" in loc:
                    self._append("Open Redirect", test_url, f"Parameter `{param}` is unsafely redirected.", evidence=f"Location: {loc}")

    def check_sqli_error_based(self):
        for base in self._paths_for_testing():
            for param in self.sqli_params:
                for payload in self.sqli_payloads:
                    parsed = urlparse(base)
                    q = dict(parse_qsl(parsed.query))
                    q[param] = payload
                    test_url = parsed._replace(query=urlencode(q, doseq=True)).geturl()
                    resp = self._get(test_url)
                    if resp and resp.text and self._sql_error_re.search(resp.text):
                        self._append("SQL Injection", test_url, f"DB error pattern after injecting `{param}`.", evidence=self._sql_error_re.search(resp.text).group(0))
                        # don’t hammer — move on to next param/path
                        break

    def check_path_traversal(self):
        # try combinations of traversal prefixes + target files + encodings
        candidates = []
        for base in self._paths_for_testing():
            for t in self.traversal_targets:
                t_norm = t.lstrip("/")
                # plain prefixes
                for pref in self.traversal_prefixes:
                    candidates.append(urljoin(base, pref + t_norm))
                # encoded variants like "..%2f"
                depth = 6
                for enc in self.traversal_enc:
                    prefix = enc * depth
                    candidates.append(urljoin(base + "/", prefix + t_norm))
        for u in uniq(candidates)[:200]:  # cap to be polite
            resp = self._get(u)
            if not resp or resp.status_code >= 500:
                continue
            body = resp.text[:2000]
            if "/etc/passwd" in u and re.search(r"\broot:.*:0:0:", body):
                self._append("Path Traversal", u, "Unix passwd content signature found.", evidence=body[:200])
                return
            if "win.ini" in u.lower() and ("[fonts]" in body.lower() or "[extensions]" in body.lower()):
                self._append("Path Traversal", u, "Windows INI content signature found.", evidence=body[:200])
                return

    def check_reflected_xss_signal(self):
        # safe reflection test with unique token, no script execution
        token = f"simon{int(time.time())}{random.randint(1000,9999)}x"
        for base in self._paths_for_testing():
            for param in self.xss_params:
                parsed = urlparse(base)
                q = dict(parse_qsl(parsed.query))
                q[param] = token
                test_url = parsed._replace(query=urlencode(q, doseq=True)).geturl()
                resp = self._get(test_url)
                if resp and token in resp.text:
                    self._append("Reflected Input (possible XSS)", test_url,
                                 f"Parameter `{param}` value reflected without encoding.", evidence=f"...{token}...")
                    # don’t over-report; single signal is enough for this path
                    break

# --------------------------- reporting ---------------------------

def generate_report(filename, target, findings):
    doc = SimpleDocTemplate(filename, pagesize=letter, title="Vulnerability Assessment Report")
    styles = getSampleStyleSheet()
    from reportlab.lib.styles import ParagraphStyle
    styles.add(ParagraphStyle(name='SeverityHeading', parent=styles['Heading2'], alignment=TA_CENTER))

    elements = []
    elements.append(Paragraph("Vulnerability Assessment Report", styles['Title']))
    elements.append(Spacer(1, 10))
    meta_tbl = Table([
        ["Target", target],
        ["Scan Date (UTC)", now_iso()],
        ["Totals", f"High: {len(findings['High'])}   Medium: {len(findings['Medium'])}   Low: {len(findings['Low'])}"]
    ], colWidths=[130, 400])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
        ("BOX", (0,0), (-1,-1), 0.5, colors.black),
        ("INNERGRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    elements.append(meta_tbl)
    elements.append(Spacer(1, 14))

    order = ["High", "Medium", "Low"]
    for sev in order:
        vulns = findings.get(sev, [])
        if not vulns:
            continue
        elements.append(Paragraph(f"{sev} Risk Findings", styles['SeverityHeading']))
        elements.append(Spacer(1, 6))
        for v in vulns:
            elements.append(Paragraph(f"<b>Type:</b> {v['type']}", styles['Heading3']))
            elements.append(Paragraph(f"<b>URL:</b> {v['url']}", styles['BodyText']))
            elements.append(Paragraph(f"<b>Description:</b> {v['description']}", styles['BodyText']))
            if v.get("evidence"):
                elements.append(Paragraph(f"<b>Evidence:</b> <font face='Courier'>{v['evidence']}</font>", styles['BodyText']))
            elements.append(Spacer(1, 8))
        elements.append(Spacer(1, 8))
    if not any(findings.values()):
        elements.append(Paragraph("No vulnerabilities found.", styles['BodyText']))
    doc.build(elements)

# --------------------------- main ---------------------------

def main():
    print_banner()
    p = argparse.ArgumentParser(description="S!M0N vuln-scanner: payload-powered web vulnerability scanner with PDF report.")
    p.add_argument("-d", "--domain", required=True, help="Target website URL (e.g., https://example.com)")
    p.add_argument("-o", "--output", default="vulnerability_report.pdf", help="Output PDF filename")
    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)")
    p.add_argument("--threads", type=int, default=8, help="Max concurrent checks (default: 8)")
    p.add_argument("--payload-dir", default="payloads", help="Directory containing payload .txt files")
    args = p.parse_args()

    # basic safety reminder
    parsed = urlparse(args.domain)
    if not parsed.scheme.startswith("http"):
        print("[!] Please provide a valid http(s) URL.")
        sys.exit(2)

    scanner = VulnerabilityScanner(args.domain, timeout=args.timeout, threads=args.threads, payload_dir=args.payload_dir)
    findings = scanner.scan()
    generate_report(args.output, args.domain, findings)
    print(f"[+] Scan complete. Report generated: {args.output}")
    print(f"[i] Totals → High: {len(findings['High'])} | Medium: {len(findings['Medium'])} | Low: {len(findings['Low'])}")

if __name__ == "__main__":
    main()
