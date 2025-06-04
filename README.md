# 🛡️ S!M0N - Vulnerability Scanner

**S!M0N** is a Python-based web vulnerability scanner built for ethical hackers, bug bounty hunters, and security researchers. It detects and classifies 15+ common web security flaws (Low, Medium, High risk) and generates professional-grade reports.

---

## 🚀 Features

- 🔍 Scans for 15+ real-world vulnerabilities
- 🧠 Risk-based categorization (Low / Medium / High)
- 📄 Auto-generates detailed PDF vulnerability reports
- 🖥️ Sleek command-line interface with banner
- 🔧 Lightweight and fast — built for automation

---

## 📊 Vulnerabilities Checked

| 🔐 Risk  | 🕷️ Vulnerability             | 🧾 Description                                        |
|---------|-----------------------------|------------------------------------------------------|
| **Low** | Server Version Disclosure    | Server/version info in HTTP headers                  |
|         | Clickjacking                 | Missing `X-Frame-Options` or CSP frame policies      |
|         | Directory Listing            | Open directory indexing enabled                      |
|         | Internal IP Disclosure       | Leaks private IPs (e.g., `192.168.x.x`)              |
|         | Verbose Error Messages       | Stack traces or debug info exposed                   |
| **Medium** | Open Redirect            | Redirects to untrusted external domains              |
|         | Insecure Cookies             | Missing `Secure`, `HttpOnly`, or `SameSite` flags    |
|         | CSRF                         | No anti-CSRF protection mechanisms                   |
|         | Broken Access Controls       | Access to unauthorized low-privileged data           |
|         | Missing Rate Limiting        | No throttling on sensitive endpoints                 |
|         | CORS Misconfiguration        | Wildcard or unsafe domain access allowed             |
| **High** | SQL Injection              | Database manipulation or data theft                  |
|         | Remote Code Execution (RCE)  | Arbitrary command execution on the server            |
|         | Command Injection            | OS command execution via input injection             |
|         | Authentication Bypass        | Unauthorized login or privilege escalation           |
|         | File Upload Vulnerability    | Upload of malicious scripts                          |
|         | Path Traversal               | Arbitrary file read/write (`../../etc/passwd`)       |
|         | Broken Object Level Auth     | Unauthorized access to other users' objects/data     |

---

## ⚙️ Installation

git clone https://github.com/mrgrey0001/Simon_vs.git
cd Simon_vs
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

## 🧪 Usage

python simon.py -d [https://example.com] -l [2] -o [example_scan_report.pdf] --subdomains --threads [15]

-d : Target domain (e.g., http://example.com, https://www.mysite.org)
-l : Crawl level (depth of URL crawling, default: 1)
-o : Output PDF file name (default: vulnerability_report.pdf)
--subdomains : Enable subdomain discovery for the target domain (optional)
--threads : Number of threads for concurrent scanning (default: 10)



---

## 🧠 Disclaimer

This tool is for **educational and authorized security testing only**. Do **not** use it against systems without explicit permission.

---

🛠️ **This tool is under development.**
