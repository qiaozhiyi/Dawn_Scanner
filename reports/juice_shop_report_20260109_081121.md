# Dawn Scanner Report - OWASP Juice Shop

- Target: http://host.docker.internal:3000
- Task ID: task_1767946276768123875
- Status: completed
- Summary: Found vulnerabilities: 1 high severity, 1 medium severity
- Baseline: Juice Shop challenges.yml (version 19.1.1)

## Baseline Coverage
- Categories in baseline: 13
- Categories covered by scan: 2
- Coverage: 15.4%

### Covered Categories
- Command Injection
- XSS

### Missing Categories (with sample challenges)
- Auth/Session: Bjoern's Favorite Pet, Blockchain Hype, NFT Takeover, Empty User Registration, Forged Signed JWT
- CSRF: CSRF
- Crypto/Secrets: Outdated Allowlist, Weird Crypto, Leaked API Key
- File Upload: Access Log, Arbitrary File Write, Forgotten Developer Backup, Forgotten Sales Backup, Misplaced Signature File
- Info Disclosure: Email Leak, Leaked Unsafe Product, Exposed credentials
- Misconfiguration: Error Handling
- Other: Admin Registration, Admin Section, Mint the Honey Pot, Wallet Depletion, Web3 Sandbox
- SQL Injection: Change Bender's Password, Database Schema, Login Bjoern, Login MC SafeSearch, Login Support Team
- SSRF: SSRF
- TLS/HTTPS: Easter Egg, Premium Paywall, Product Tampering, Cross-Site Imaging, Exposed Metrics
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
