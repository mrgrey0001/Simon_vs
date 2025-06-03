# S!M0N vuln-scanner

A Python-based web vulnerability scanner that detects common web security issues (Low, Medium, High risk) and generates a detailed report.

## Features

- Detects 15+ web vulnerabilities (see below)
- Categorizes findings by risk (Low, Medium, High)
- PDF report output
- Command-line interface with banner

## Vulnerabilities Checked

| Risk    | Vulnerability                | Description                                         |
|---------|-----------------------------|-----------------------------------------------------|
| Low     | Server Version Disclosure    | Server/version in headers                           |
| Low     | Clickjacking                 | No X-Frame-Options or CSP frame policy              |
| Low     | Directory Listing            | Indexes enabled                                     |
| Low     | Internal IP Disclosure       | 192.168.x.x, 10.x.x.x in response                   |
| Low     | Verbose Error Messages       | Stack traces or debug info visible                  |
| Medium  | Open Redirect                | Redirects to arbitrary URLs                         |
| Medium  | Insecure Cookies             | Missing Secure/HttpOnly/SameSite                    |
| Medium  | CSRF                         | No anti-CSRF tokens                                 |
| Medium  | Broken Access Controls (Minor)| Unauthorized access to low-privileged data         |
| Medium  | Missing Rate Limiting        | No limits on login/critical endpoints               |
| Medium  | CORS Misconfiguration        | Cross-origin access from unauthorized domains       |
| High    | SQL Injection                | DB manipulation/data exfiltration                   |
| High    | Remote Code Execution (RCE)  | Run system commands remotely                        |
| High    | Command Injection            | OS command injection via input                      |
| High    | Authentication Bypass        | Login/privilege escalation without credentials      |
| High    | File Upload Vulnerability    | Uploading malicious scripts                         |
| High    | Path Traversal               | Read/write sensitive files (../../etc/passwd)       |
| High    | Broken Object Level Auth     | Access to other users' records/objects              |

## Installation

git clone https://github.com/mrgrey0001/Simon_vs.git
cd Simon_vs
pip install -r requirements.txt
