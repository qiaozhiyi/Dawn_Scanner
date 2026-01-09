# Dawn Scanner Report - OWASP Juice Shop

- Target: http://host.docker.internal:3000
- Task ID: task_1767946373315976753
- Status: completed
- Summary: Found vulnerabilities: 1 high severity, 1 medium severity
- Baseline: Juice Shop challenges.yml (version 19.1.1)

## Baseline Coverage
- Categories in baseline: 14
- Categories covered by scan: 2
- Coverage: 14.3%

### Covered Categories
- Security Headers
- TLS/HTTPS

### Missing Categories (with sample challenges)
- Auth/Session: Bjoern's Favorite Pet, Blockchain Hype, NFT Takeover, Empty User Registration, Forged Signed JWT
- CSRF: CSRF
- Command Injection: Blocked RCE DoS, Login Amy, Successful RCE DoS, Allowlist Bypass
- Crypto/Secrets: Outdated Allowlist, Weird Crypto, Leaked API Key
- File Upload: Access Log, Arbitrary File Write, Forgotten Developer Backup, Forgotten Sales Backup, Upload Size
- Info Disclosure: Email Leak, Leaked Unsafe Product, Exposed credentials
- Misconfiguration: Error Handling
- Other: Admin Registration, Admin Section, Mint the Honey Pot, Wallet Depletion, Web3 Sandbox
- SQL Injection: Change Bender's Password, Database Schema, Login Bjoern, Login MC SafeSearch, Login Support Team
- SSRF: SSRF
- XSS: API-only XSS, Client-side XSS Protection, DOM XSS, Reflected XSS, Server-side XSS Protection
- XXE: XXE Data Access, XXE DoS

## Vulnerabilities
### 1. SSL/TLS Missing
- Severity: High
- URL: http://host.docker.internal:3000/
- Description: Site does not use HTTPS encryption
- Details: The website does not use HTTPS, making data transmission vulnerable to interception

### 2. Missing Security Headers
- Severity: Medium
- URL: http://host.docker.internal:3000/
- Description: Missing important security headers: X-XSS-Protection (cross-site scripting), Content-Security-Policy (script injection)
- Details: The server does not implement important security headers that protect against common attacks

## LLM Report
Initial scan report generated
