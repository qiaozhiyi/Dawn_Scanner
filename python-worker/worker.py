"""
Dawn Scanner - Python Worker Module
This module handles the actual vulnerability scanning tasks
"""

import asyncio
import aiohttp
import logging
import json
import os
import sys
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import subprocess
import socket
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Represents the result of a vulnerability scan"""
    url: str
    vulnerabilities: List[Dict]
    summary: str
    timestamp: str
    scan_duration: float


class VulnerabilityScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self):
        self.session = None
        self.timeout = int(os.getenv('SCAN_TIMEOUT', '300'))  # 5 minutes default
        self.max_crawl_pages = int(os.getenv('MAX_CRAWL_PAGES', '30'))
        self.max_param_tests = int(os.getenv('MAX_PARAM_TESTS', '50'))
        self.auth_headers: Optional[Dict] = None
        self.user_id: Optional[int] = None
        self.basket_id: Optional[int] = None
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _fetch_text(self, url: str, headers: Optional[Dict] = None) -> Tuple[int, Dict, str]:
        """Fetch URL content with basic error handling."""
        if headers is None:
            headers = {}
        if self.auth_headers:
            headers = {**self.auth_headers, **headers}
        try:
            async with self.session.get(url, headers=headers, allow_redirects=True) as response:
                text = await response.text(errors='ignore')
                return response.status, dict(response.headers), text
        except Exception as e:
            logger.debug(f"Fetch failed for {url}: {e}")
            return 0, {}, ""

    async def _post_text(self, url: str, data: str, headers: Optional[Dict] = None) -> Tuple[int, Dict, str]:
        """POST raw payload and return response text."""
        if headers is None:
            headers = {}
        if self.auth_headers:
            headers = {**self.auth_headers, **headers}
        try:
            async with self.session.post(url, data=data, headers=headers) as response:
                text = await response.text(errors='ignore')
                return response.status, dict(response.headers), text
        except Exception as e:
            logger.debug(f"POST failed for {url}: {e}")
            return 0, {}, ""

    async def _get_json(self, url: str, headers: Optional[Dict] = None) -> Tuple[int, Dict, Dict]:
        """GET JSON response."""
        if headers is None:
            headers = {}
        if self.auth_headers:
            headers = {**self.auth_headers, **headers}
        try:
            async with self.session.get(url, headers=headers) as response:
                data = await response.json(content_type=None)
                return response.status, dict(response.headers), data
        except Exception as e:
            logger.debug(f"GET JSON failed for {url}: {e}")
            return 0, {}, {}

    async def _post_json(self, url: str, json_body: Dict, headers: Optional[Dict] = None) -> Tuple[int, Dict, Dict]:
        """POST JSON body and return JSON response."""
        if headers is None:
            headers = {}
        if self.auth_headers:
            headers = {**self.auth_headers, **headers}
        try:
            async with self.session.post(url, json=json_body, headers=headers) as response:
                data = await response.json(content_type=None)
                return response.status, dict(response.headers), data
        except Exception as e:
            logger.debug(f"POST JSON failed for {url}: {e}")
            return 0, {}, {}

    def _same_origin(self, base_url: str, target_url: str) -> bool:
        """Check if target URL is within the same origin as base URL."""
        base = urlparse(base_url)
        target = urlparse(target_url)
        return base.scheme == target.scheme and base.netloc == target.netloc

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract href/src/action links from HTML."""
        links = set()
        for attr in ['href', 'src', 'action']:
            for match in re.findall(rf'{attr}\s*=\s*["\'](.*?)["\']', html, flags=re.IGNORECASE):
                links.add(match)
        resolved = set()
        for link in links:
            if not link or link.startswith('#') or link.startswith('javascript:'):
                continue
            resolved_url = urljoin(base_url, link)
            if not resolved_url.startswith('http'):
                continue
            resolved.add(resolved_url.split('#')[0])
        return resolved

    async def crawl_site(self, base_url: str) -> List[str]:
        """Crawl the site to discover URLs for scanning."""
        visited = set()
        queue = [base_url]

        while queue and len(visited) < self.max_crawl_pages:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            status, _, text = await self._fetch_text(current)
            if status >= 400 or not text:
                continue

            for link in self._extract_links(text, current):
                if self._same_origin(base_url, link) and link not in visited:
                    queue.append(link)

        # Pull URLs from robots.txt and sitemap.xml if present.
        for extra in ["robots.txt", "sitemap.xml"]:
            extra_url = urljoin(base_url.rstrip("/") + "/", extra)
            status, _, text = await self._fetch_text(extra_url)
            if status < 400 and text:
                for line in text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        queue.append(sitemap_url)
                    if "http" in line:
                        for token in line.split():
                            if token.startswith("http") and self._same_origin(base_url, token):
                                visited.add(token)

        return sorted(visited)

    async def get_auth_headers(self, base_url: str) -> Optional[Dict]:
        """Auto-register/login for Juice Shop to get auth headers."""
        try:
            # Simple heuristic: Juice Shop exposes /rest and /api/Users
            test_url = urljoin(base_url.rstrip("/") + "/", "rest/user/login")
            status, _, _ = await self._fetch_text(test_url, headers={})
            if status == 0:
                return None

            email = f"dawn_{int(datetime.now().timestamp())}@example.com"
            password = "DawnScanner!123"

            register_url = urljoin(base_url.rstrip("/") + "/", "api/Users")
            register_payload = {
                "email": email,
                "password": password,
                "passwordRepeat": password,
                "securityQuestion": {
                    "id": 1,
                    "answer": "scanner"
                }
            }
            try:
                async with self.session.post(register_url, json=register_payload) as resp:
                    await resp.text()
            except Exception:
                pass

            login_url = urljoin(base_url.rstrip("/") + "/", "rest/user/login")
            login_payload = {"email": email, "password": password}
            async with self.session.post(login_url, json=login_payload) as resp:
                data = await resp.json()
                token = data.get("authentication", {}).get("token")
                if token:
                    return {"Authorization": f"Bearer {token}"}
        except Exception as e:
            logger.warning(f"Auto-login failed: {e}")
        return None


    async def populate_auth_context(self, base_url: str) -> None:
        """Populate user_id and basket_id for authenticated actions."""
        if not self.auth_headers:
            return
        whoami_url = urljoin(base_url.rstrip("/") + "/", "rest/user/whoami")
        status, _, data = await self._get_json(whoami_url)
        if status == 0 or not data:
            return
        user = data.get("user") or {}
        self.user_id = user.get("id")
        self.basket_id = data.get("basketId")

    def generate_seed_urls(self, base_url: str) -> List[str]:
        """Generate common parameterized URLs to deepen checks."""
        seeds = [
            "/search?q=test",
            "/?q=test",
            "/?search=test",
            "/?id=1",
            "/?page=1",
            "/api/search?q=test",
            "/api/items?id=1",
            "/api/products/search?q=test",
            "/api/v1/search?q=test",
            "/rest/products/search?q=test",
            "/rest/products/search?q=1",
            "/rest/basket/1",
            "/rest/user/whoami?token=test",
            "/rest/track-order/1",
            "/rest/track-order/1?orderId=1",
            "/api/track-order/1",
            "/api/track-order/1?orderId=1",
            "/redirect?url=http://example.com",
            "/proxy?url=http://example.com",
            "/fetch?url=http://example.com",
            "/callback?url=http://example.com",
            "/rest/redirect?url=http://example.com",
        ]
        return [urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) for path in seeds]


    async def scan_url(self, url: str) -> ScanResult:
        """
        Perform a comprehensive vulnerability scan on the given URL
        """
        logger.info(f"Starting scan for URL: {url}")
        start_time = datetime.now()
        
        try:
            # Validate URL
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid URL: {url}")
            
            # Initialize vulnerabilities list
            vulnerabilities = []
            
            # Check for basic connectivity
            connectivity_ok = await self.check_connectivity(url)
            if not connectivity_ok:
                logger.warning(f"Could not connect to {url}")
                return ScanResult(
                    url=url,
                    vulnerabilities=[],
                    summary=f"Could not connect to {url}",
                    timestamp=start_time.isoformat(),
                    scan_duration=(datetime.now() - start_time).total_seconds()
                )
            
            # Optional auth for Juice Shop (auto-register/login)
            self.auth_headers = await self.get_auth_headers(url)
            await self.populate_auth_context(url)

            # Discover URLs for deeper checks
            crawl_urls = await self.crawl_site(url)
            crawl_urls.extend(self.generate_seed_urls(url))
            crawl_urls = list(dict.fromkeys(crawl_urls))

            api_endpoints = await self.discover_api_endpoints(url, crawl_urls)

            # Perform various security checks
            vulnerabilities.extend(await self.check_ssl_security(url))
            vulnerabilities.extend(await self.check_headers_security(url))
            vulnerabilities.extend(await self.check_cookie_security(url))
            vulnerabilities.extend(await self.check_cors_misconfig(url))
            vulnerabilities.extend(await self.check_server_info_disclosure(url))
            vulnerabilities.extend(await self.check_reflected_xss(crawl_urls))
            vulnerabilities.extend(await self.check_sqli_errors(crawl_urls))
            vulnerabilities.extend(await self.check_sqli_heuristics(crawl_urls))
            vulnerabilities.extend(await self.check_csrf_on_forms(crawl_urls))
            vulnerabilities.extend(await self.check_form_xss_and_sqli(crawl_urls))
            vulnerabilities.extend(await self.check_file_upload_forms(crawl_urls))
            vulnerabilities.extend(await self.check_access_control(url))
            vulnerabilities.extend(await self.check_ssrf_parameters(crawl_urls))
            vulnerabilities.extend(await self.check_xxe_endpoints(crawl_urls))
            vulnerabilities.extend(await self.check_rest_search_probes(url))
            vulnerabilities.extend(await self.check_open_redirects(crawl_urls))
            vulnerabilities.extend(await self.check_path_traversal(crawl_urls))
            vulnerabilities.extend(await self.check_json_endpoint_fuzzing(api_endpoints))
            vulnerabilities.extend(await self.perform_authenticated_actions(url))
            vulnerabilities.extend(await self.check_common_vulnerabilities(url))
            
            # Generate summary
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Medium')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            summary_parts = []
            for severity, count in severity_counts.items():
                if count > 0:
                    summary_parts.append(f"{count} {severity.lower()} severity")
            
            if not summary_parts:
                summary = "No vulnerabilities detected"
            else:
                summary = f"Found vulnerabilities: {', '.join(summary_parts)}"
                
            scan_duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Scan completed for {url} in {scan_duration:.2f}s")
            
            return ScanResult(
                url=url,
                vulnerabilities=vulnerabilities,
                summary=summary,
                timestamp=start_time.isoformat(),
                scan_duration=scan_duration
            )
            
        except Exception as e:
            logger.error(f"Error scanning {url}: {str(e)}")
            return ScanResult(
                url=url,
                vulnerabilities=[{
                    'id': 'scan-error',
                    'type': 'Scan Error',
                    'severity': 'Critical',
                    'description': f'Scan failed: {str(e)}',
                    'url': url,
                    'details': str(e)
                }],
                summary=f'Scan failed: {str(e)}',
                timestamp=start_time.isoformat(),
                scan_duration=(datetime.now() - start_time).total_seconds()
            )


    async def check_connectivity(self, url: str) -> bool:
        """Check if the URL is reachable"""
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                logger.info(f"Connectivity check for {url}: {response.status}")
                return response.status < 400
        except Exception as e:
            logger.warning(f"Connectivity check failed for {url}: {e}")
            return False


    async def check_ssl_security(self, url: str) -> List[Dict]:
        """Check SSL/TLS security configurations"""
        vulnerabilities = []
        
        if not url.startswith('https'):
            vulnerabilities.append({
                'id': 'ssl-missing',
                'type': 'SSL/TLS Missing',
                'severity': 'High',
                'description': 'Site does not use HTTPS encryption',
                'url': url,
                'details': 'The website does not use HTTPS, making data transmission vulnerable to interception'
            })
            return vulnerabilities
        
        # In a real implementation, we would perform detailed SSL checks
        # For now, we'll simulate checking for common SSL issues
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Check if SSL certificate is valid (simulated)
            ssl_issues = self._check_ssl_certificate(hostname, port)
            if ssl_issues:
                vulnerabilities.extend(ssl_issues)
                
        except Exception as e:
            logger.warning(f"SSL check failed for {url}: {e}")
        
        return vulnerabilities


    def _check_ssl_certificate(self, hostname: str, port: int) -> List[Dict]:
        """Simulate SSL certificate checks"""
        # This is a simplified simulation
        # In a real implementation, we would use libraries like ssl, cryptography, etc.
        vulnerabilities = []
        
        # Simulate checking for common SSL issues
        # For demonstration purposes, we'll return some common SSL vulnerabilities
        return []


    async def check_headers_security(self, url: str) -> List[Dict]:
        """Check security headers"""
        vulnerabilities = []
        
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                
                # Check for missing security headers
                missing_headers = []
                
                if 'X-Frame-Options' not in headers:
                    missing_headers.append('X-Frame-Options (clickjacking protection)')
                    vulnerabilities.append({
                        'id': 'clickjacking-protection-missing',
                        'type': 'Clickjacking Protection Missing',
                        'severity': 'Medium',
                        'description': 'X-Frame-Options header is missing',
                        'url': url,
                        'details': 'Missing X-Frame-Options can allow UI redressing attacks'
                    })
                    
                if 'X-Content-Type-Options' not in headers:
                    missing_headers.append('X-Content-Type-Options (MIME-type confusion)')
                    
                if 'X-XSS-Protection' not in headers:
                    missing_headers.append('X-XSS-Protection (cross-site scripting)')
                    
                if 'Strict-Transport-Security' not in headers and url.startswith('https'):
                    missing_headers.append('Strict-Transport-Security (HSTS)')
                    vulnerabilities.append({
                        'id': 'hsts-missing',
                        'type': 'HSTS Missing',
                        'severity': 'Low',
                        'description': 'Strict-Transport-Security header is missing',
                        'url': url,
                        'details': 'HSTS helps enforce HTTPS and reduce downgrade risks'
                    })
                    
                if 'Content-Security-Policy' not in headers:
                    missing_headers.append('Content-Security-Policy (script injection)')
                    vulnerabilities.append({
                        'id': 'csp-missing',
                        'type': 'Content Security Policy Missing',
                        'severity': 'Medium',
                        'description': 'Content-Security-Policy header is missing',
                        'url': url,
                        'details': 'CSP reduces impact of XSS and script injection'
                    })
                
                if missing_headers:
                    vulnerabilities.append({
                        'id': 'missing-security-headers',
                        'type': 'Missing Security Headers',
                        'severity': 'Medium',
                        'description': f'Missing important security headers: {", ".join(missing_headers)}',
                        'url': url,
                        'details': f'The server does not implement important security headers that protect against common attacks'
                    })
                    
        except Exception as e:
            logger.warning(f"Header check failed for {url}: {e}")
        
        return vulnerabilities


    async def check_cookie_security(self, url: str) -> List[Dict]:
        """Check for insecure session cookie settings"""
        vulnerabilities = []
        try:
            async with self.session.get(url) as response:
                cookies = response.headers.getall('Set-Cookie', [])
                for cookie in cookies:
                    lower = cookie.lower()
                    missing = []
                    if 'httponly' not in lower:
                        missing.append('HttpOnly')
                    if url.startswith('https') and 'secure' not in lower:
                        missing.append('Secure')
                    if 'samesite' not in lower:
                        missing.append('SameSite')
                    if missing:
                        vulnerabilities.append({
                            'id': 'cookie-flags-missing',
                            'type': 'Insecure Session Cookie',
                            'severity': 'Medium',
                            'description': f'Session cookie missing flags: {", ".join(missing)}',
                            'url': url,
                            'details': 'Missing cookie flags can lead to session theft or CSRF attacks'
                        })
                        break
        except Exception as e:
            logger.warning(f"Cookie security check failed for {url}: {e}")
        return vulnerabilities


    async def check_cors_misconfig(self, url: str) -> List[Dict]:
        """Check for overly permissive CORS settings"""
        vulnerabilities = []
        try:
            headers = {'Origin': 'http://evil.example'}
            async with self.session.get(url, headers=headers) as response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acc = response.headers.get('Access-Control-Allow-Credentials', '')

                if acao == '*':
                    severity = 'Medium'
                    if acc.lower() == 'true':
                        severity = 'High'
                    vulnerabilities.append({
                        'id': 'cors-wildcard',
                        'type': 'Overly Permissive CORS',
                        'severity': severity,
                        'description': 'CORS allows requests from any origin',
                        'url': url,
                        'details': 'Wildcard Access-Control-Allow-Origin can enable cross-origin data access'
                    })
                elif acao == 'http://evil.example' and acc.lower() == 'true':
                    vulnerabilities.append({
                        'id': 'cors-reflect',
                        'type': 'Overly Permissive CORS',
                        'severity': 'Medium',
                        'description': 'CORS reflects arbitrary Origin with credentials enabled',
                        'url': url,
                        'details': 'Reflecting Origin with credentials can expose authenticated data'
                    })
        except Exception as e:
            logger.warning(f"CORS check failed for {url}: {e}")
        return vulnerabilities


    async def check_server_info_disclosure(self, url: str) -> List[Dict]:
        """Check for server header information disclosure"""
        vulnerabilities = []
        try:
            async with self.session.get(url) as response:
                server = response.headers.get('Server')
                powered = response.headers.get('X-Powered-By')
                if server or powered:
                    details = []
                    if server:
                        details.append(f"Server: {server}")
                    if powered:
                        details.append(f"X-Powered-By: {powered}")
                    vulnerabilities.append({
                        'id': 'server-info-disclosure',
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': 'Server software information is exposed',
                        'url': url,
                        'details': '; '.join(details)
                    })
        except Exception as e:
            logger.warning(f"Server info check failed for {url}: {e}")
        return vulnerabilities


    async def check_reflected_xss(self, urls: List[str]) -> List[Dict]:
        """Check for basic reflected XSS patterns on query parameters"""
        vulnerabilities = []
        payload = "dawnxss123"

        tested_urls = 0
        for target in urls:
            parsed = urlparse(target)
            if not parsed.query:
                continue
            tested_urls += 1
            if tested_urls > self.max_param_tests:
                break
            params = parse_qs(parsed.query, keep_blank_values=True)
            for key in params.keys():
                test_params = {k: v for k, v in params.items()}
                test_params[key] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                status, _, text = await self._fetch_text(test_url)
                if status < 400 and payload in text:
                    vulnerabilities.append({
                        'id': 'reflected-xss',
                        'type': 'Reflected XSS',
                        'severity': 'High',
                        'description': f'Potential reflected XSS via parameter: {key}',
                        'url': test_url,
                        'details': 'Injected payload appears in response without encoding'
                    })
                    break
        return vulnerabilities


    async def check_sqli_errors(self, urls: List[str]) -> List[Dict]:
        """Check for basic SQL error messages in responses"""
        vulnerabilities = []
        error_patterns = [
            'sql syntax', 'mysql', 'sqlite', 'postgres', 'psql',
            'odbc', 'jdbc', 'syntax error', 'sqlstate'
        ]

        tested_urls = 0
        for target in urls:
            parsed = urlparse(target)
            if not parsed.query:
                continue
            tested_urls += 1
            if tested_urls > self.max_param_tests:
                break
            params = parse_qs(parsed.query, keep_blank_values=True)
            for key in params.keys():
                test_params = {k: v for k, v in params.items()}
                test_params[key] = ["'"]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                status, _, text = await self._fetch_text(test_url)
                if status == 0:
                    continue
                lower = text.lower()
                if any(pat in lower for pat in error_patterns):
                    vulnerabilities.append({
                        'id': 'sqli-error-based',
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': f'Potential SQL injection in parameter: {key}',
                        'url': test_url,
                        'details': 'SQL error pattern detected in response'
                    })
                    break
        return vulnerabilities


    async def check_csrf_on_forms(self, urls: List[str]) -> List[Dict]:
        """Check for forms missing CSRF tokens"""
        vulnerabilities = []
        token_keywords = ['csrf', 'token', 'authenticity']

        for target in urls:
            status, _, text = await self._fetch_text(target)
            if status >= 400 or not text:
                continue

            for match in re.finditer(r'<form([^>]*)>(.*?)</form>', text, flags=re.IGNORECASE | re.DOTALL):
                attrs = match.group(1)
                body = match.group(2)
                method_match = re.search(r'method\s*=\s*["\'](.*?)["\']', attrs, flags=re.IGNORECASE)
                method = method_match.group(1).lower() if method_match else 'get'
                if method != 'post':
                    continue

                if not any(kw in body.lower() for kw in token_keywords):
                    vulnerabilities.append({
                        'id': 'csrf-missing-token',
                        'type': 'CSRF Token Missing',
                        'severity': 'Medium',
                        'description': 'Form submission without CSRF token detected',
                        'url': target,
                        'details': 'POST form lacks typical CSRF token fields'
                    })
                    break

        return vulnerabilities


    def _parse_forms(self, html: str, base_url: str) -> List[Dict]:
        """Parse basic form metadata from HTML."""
        forms = []
        for match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, flags=re.IGNORECASE | re.DOTALL):
            attrs = match.group(1)
            body = match.group(2)
            action_match = re.search(r'action\s*=\s*["\'](.*?)["\']', attrs, flags=re.IGNORECASE)
            method_match = re.search(r'method\s*=\s*["\'](.*?)["\']', attrs, flags=re.IGNORECASE)
            enctype_match = re.search(r'enctype\s*=\s*["\'](.*?)["\']', attrs, flags=re.IGNORECASE)

            action = action_match.group(1).strip() if action_match else base_url
            method = method_match.group(1).strip().lower() if method_match else 'get'
            enctype = enctype_match.group(1).strip().lower() if enctype_match else ''

            inputs = []
            for inp in re.finditer(r'<input([^>]*)>', body, flags=re.IGNORECASE):
                attrs_in = inp.group(1)
                name_match = re.search(r'name\s*=\s*["\'](.*?)["\']', attrs_in, flags=re.IGNORECASE)
                type_match = re.search(r'type\s*=\s*["\'](.*?)["\']', attrs_in, flags=re.IGNORECASE)
                value_match = re.search(r'value\s*=\s*["\'](.*?)["\']', attrs_in, flags=re.IGNORECASE)
                if not name_match:
                    continue
                inputs.append({
                    "name": name_match.group(1),
                    "type": (type_match.group(1) if type_match else "text").lower(),
                    "value": value_match.group(1) if value_match else ""
                })

            forms.append({
                "action": urljoin(base_url, action),
                "method": method,
                "enctype": enctype,
                "inputs": inputs
            })
        return forms


    async def check_form_xss_and_sqli(self, urls: List[str]) -> List[Dict]:
        """Submit form payloads to detect XSS/SQLi signals."""
        vulnerabilities = []
        xss_payload = "<svg/onload=alert('dawnxss')>"
        sqli_payloads = ["' OR '1'='1", "1' OR '1'='1", "\" OR \"1\"=\"1", "' -- "]
        error_patterns = [
            'sql syntax', 'mysql', 'sqlite', 'postgres', 'psql',
            'odbc', 'jdbc', 'syntax error', 'sqlstate'
        ]
        tested = 0

        for target in urls:
            if tested >= self.max_param_tests:
                break
            status, _, text = await self._fetch_text(target)
            if status >= 400 or not text:
                continue

            for form in self._parse_forms(text, target):
                if tested >= self.max_param_tests:
                    break
                form_inputs = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("submit", "button", "image", "file"):
                        continue
                    form_inputs[inp["name"]] = inp["value"] or "test"

                if not form_inputs:
                    continue

                # XSS probe
                xss_data = {k: xss_payload for k in form_inputs.keys()}
                status, _, resp_text = await self._post_text(form["action"], xss_data)
                tested += 1
                if status < 400 and xss_payload in resp_text:
                    vulnerabilities.append({
                        'id': 'xss-form-reflection',
                        'type': 'Reflected XSS',
                        'severity': 'High',
                        'description': 'Potential reflected XSS in form submission',
                        'url': form["action"],
                        'details': 'XSS payload appears in form response'
                    })

                # SQLi probe
                for payload in sqli_payloads:
                    sqli_data = {k: payload for k in form_inputs.keys()}
                    status, _, resp_text = await self._post_text(form["action"], sqli_data)
                    tested += 1
                    lower = resp_text.lower()
                    if any(pat in lower for pat in error_patterns) and status >= 400:
                        vulnerabilities.append({
                            'id': 'sqli-form',
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'description': 'Potential SQL injection in form submission',
                            'url': form["action"],
                            'details': 'Database error patterns detected after form payload'
                        })
                        break

        return vulnerabilities


    async def check_open_redirects(self, urls: List[str]) -> List[Dict]:
        """Check for open redirects via common parameters."""
        vulnerabilities = []
        redirect_keys = ['next', 'redirect', 'url', 'return', 'continue', 'dest']
        tested = 0

        for target in urls:
            parsed = urlparse(target)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for key in params.keys():
                if key.lower() not in redirect_keys:
                    continue
                if tested >= self.max_param_tests:
                    return vulnerabilities
                test_params = {k: v for k, v in params.items()}
                test_params[key] = ["http://example.com"]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    async with self.session.get(test_url, allow_redirects=False) as response:
                        location = response.headers.get('Location', '')
                        if location.startswith("http://example.com"):
                            vulnerabilities.append({
                                'id': 'open-redirect',
                                'type': 'Open Redirect',
                                'severity': 'Medium',
                                'description': f'Open redirect via parameter: {key}',
                                'url': test_url,
                                'details': 'Response Location header points to attacker-controlled URL'
                            })
                            return vulnerabilities
                except Exception:
                    continue
                tested += 1

        return vulnerabilities


    async def check_path_traversal(self, urls: List[str]) -> List[Dict]:
        """Check for path traversal in query parameters."""
        vulnerabilities = []
        traversal_payloads = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"]
        tested = 0

        for target in urls:
            parsed = urlparse(target)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for key in params.keys():
                if tested >= self.max_param_tests:
                    return vulnerabilities
                for payload in traversal_payloads:
                    test_params = {k: v for k, v in params.items()}
                    test_params[key] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    status, _, text = await self._fetch_text(test_url)
                    tested += 1
                    if status < 400 and "root:x:" in text:
                        vulnerabilities.append({
                            'id': 'path-traversal',
                            'type': 'Path Traversal',
                            'severity': 'High',
                            'description': f'Path traversal via parameter: {key}',
                            'url': test_url,
                            'details': 'Sensitive file contents detected in response'
                        })
                        return vulnerabilities
        return vulnerabilities


    async def discover_api_endpoints(self, base_url: str, urls: List[str]) -> List[str]:
        """Discover REST/API endpoints from HTML and known paths."""
        endpoints = set()
        for u in urls:
            status, _, text = await self._fetch_text(u)
            if status >= 400 or not text:
                continue
            for match in re.findall(r'["\'](\/(?:rest|api)\/[^"\']+)["\']', text):
                endpoints.add(urljoin(base_url, match))
        # Known Juice Shop APIs
        known = [
            "rest/products/search",
            "api/Products",
            "api/Users",
            "api/BasketItems",
            "rest/basket/1",
            "rest/user/whoami",
            "rest/user/login",
            "rest/track-order/1",
        ]
        for path in known:
            endpoints.add(urljoin(base_url.rstrip("/") + "/", path))
        return sorted(endpoints)


    async def check_json_endpoint_fuzzing(self, endpoints: List[str]) -> List[Dict]:
        """Aggressive fuzzing of JSON endpoints with common payloads."""
        vulnerabilities = []
        xss_payload = "<img src=x onerror=alert('dawnxss')>"
        sqli_payload = "1' OR '1'='1"
        ssrf_payload = "http://127.0.0.1:1/"
        traversal_payload = "../../../../../etc/passwd"
        error_patterns = [
            'sql syntax', 'sqlite', 'mysql', 'postgres', 'syntax error',
            'unexpected token', 'stack trace', 'exception'
        ]
        tested = 0

        for endpoint in endpoints:
            if tested >= self.max_param_tests:
                break

            # Query fuzzing
            query_params = {
                "q": xss_payload,
                "search": xss_payload,
                "id": sqli_payload,
                "url": ssrf_payload,
                "file": traversal_payload,
            }
            fuzz_url = endpoint
            if "?" not in fuzz_url:
                fuzz_url = f"{endpoint}?{urlencode(query_params)}"

            status, _, text = await self._fetch_text(fuzz_url)
            tested += 1
            if status >= 500 and any(p in text.lower() for p in error_patterns):
                vulnerabilities.append({
                    'id': 'json-sqli-error',
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'description': f'Potential SQL injection on {endpoint}',
                    'url': fuzz_url,
                    'details': 'Server error patterns detected after SQLi payloads'
                })
            if xss_payload in text:
                vulnerabilities.append({
                    'id': 'json-xss-reflection',
                    'type': 'Reflected XSS',
                    'severity': 'High',
                    'description': f'Potential XSS reflection on {endpoint}',
                    'url': fuzz_url,
                    'details': 'Payload reflected in response body'
                })
            if "root:x:" in text:
                vulnerabilities.append({
                    'id': 'json-path-traversal',
                    'type': 'Path Traversal',
                    'severity': 'High',
                    'description': f'Potential path traversal on {endpoint}',
                    'url': fuzz_url,
                    'details': 'Sensitive file content detected in response'
                })
            if any(p in text.lower() for p in ['connection refused', 'failed to connect', 'timed out']):
                vulnerabilities.append({
                    'id': 'json-ssrf',
                    'type': 'SSRF',
                    'severity': 'High',
                    'description': f'Potential SSRF on {endpoint}',
                    'url': fuzz_url,
                    'details': 'Backend connection error indicates server-side fetch'
                })

            # JSON body fuzzing (POST)
            post_body = {
                "q": xss_payload,
                "search": xss_payload,
                "id": sqli_payload,
                "url": ssrf_payload,
                "file": traversal_payload,
                "name": xss_payload,
                "description": xss_payload,
            }
            status, _, data = await self._post_json(endpoint, post_body)
            tested += 1
            text_dump = json.dumps(data)
            if status >= 500 and any(p in text_dump.lower() for p in error_patterns):
                vulnerabilities.append({
                    'id': 'json-sqli-error-post',
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'description': f'Potential SQL injection on {endpoint} (POST)',
                    'url': endpoint,
                    'details': 'Server error patterns detected after SQLi payloads'
                })
            if xss_payload in text_dump:
                vulnerabilities.append({
                    'id': 'json-xss-reflection-post',
                    'type': 'Reflected XSS',
                    'severity': 'High',
                    'description': f'Potential XSS reflection on {endpoint} (POST)',
                    'url': endpoint,
                    'details': 'Payload reflected in JSON response'
                })

        return vulnerabilities


    async def perform_authenticated_actions(self, base_url: str) -> List[Dict]:
        """Perform authenticated actions to reach protected endpoints."""
        vulnerabilities = []
        if not self.auth_headers:
            return vulnerabilities

        # List products and add one to basket
        products_url = urljoin(base_url.rstrip("/") + "/", "api/Products")
        status, _, data = await self._get_json(products_url)
        if status == 200 and isinstance(data, dict):
            products = data.get("data") or []
            if products:
                product_id = products[0].get("id")
                if product_id and self.basket_id:
                    basket_url = urljoin(base_url.rstrip("/") + "/", "api/BasketItems")
                    payload = {
                        "ProductId": product_id,
                        "BasketId": self.basket_id,
                        "quantity": 1
                    }
                    status, _, resp = await self._post_json(basket_url, payload)
                    if status >= 400 and resp:
                        vulnerabilities.append({
                            'id': 'auth-action-error',
                            'type': 'Authorization Check',
                            'severity': 'Low',
                            'description': 'Authenticated basket action returned error',
                            'url': basket_url,
                            'details': 'May indicate access control or input validation issues'
                        })

        return vulnerabilities


    async def check_sqli_heuristics(self, urls: List[str]) -> List[Dict]:
        """Heuristic SQLi detection using response differences and error hints."""
        vulnerabilities = []
        payloads = ["'", "1'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' AND 1=2 -- ", "\" AND 1=2 -- "]
        error_patterns = [
            'sql syntax', 'mysql', 'sqlite', 'postgres', 'psql',
            'odbc', 'jdbc', 'syntax error', 'sqlstate'
        ]
        tested = 0

        for target in urls:
            parsed = urlparse(target)
            if not parsed.query:
                continue

            base_status, _, base_text = await self._fetch_text(target)
            if base_status == 0:
                continue

            params = parse_qs(parsed.query, keep_blank_values=True)
            for key in params.keys():
                if tested >= self.max_param_tests:
                    return vulnerabilities
                for payload in payloads:
                    test_params = {k: v for k, v in params.items()}
                    test_params[key] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    status, _, text = await self._fetch_text(test_url)
                    if status == 0:
                        continue

                    tested += 1
                    lower = text.lower()
                    if any(pat in lower for pat in error_patterns):
                        vulnerabilities.append({
                            'id': 'sqli-heuristic',
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'description': f'Potential SQL injection in parameter: {key}',
                            'url': test_url,
                            'details': 'Database error patterns detected after payload injection'
                        })
                        break

                    if base_text:
                        diff_ratio = abs(len(text) - len(base_text)) / max(len(base_text), 1)
                        if diff_ratio > 0.3 and status >= 400:
                            vulnerabilities.append({
                                'id': 'sqli-heuristic',
                                'type': 'SQL Injection',
                                'severity': 'Medium',
                                'description': f'Potential SQL injection behavior in parameter: {key}',
                                'url': test_url,
                                'details': 'Response length and status changed significantly after payload injection'
                            })
                            break
        return vulnerabilities


    async def check_ssrf_parameters(self, urls: List[str]) -> List[Dict]:
        """Detect SSRF-like behavior in URL parameters."""
        vulnerabilities = []
        ssrf_keys = ['url', 'uri', 'link', 'target', 'dest', 'redirect', 'callback', 'next']
        error_markers = [
            'connection refused', 'econnrefused', 'failed to connect',
            'timed out', 'connection timeout', 'invalid url'
        ]
        tested = 0

        for target in urls:
            parsed = urlparse(target)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query, keep_blank_values=True)

            for key in params.keys():
                if key.lower() not in ssrf_keys:
                    continue
                if tested >= self.max_param_tests:
                    return vulnerabilities
                test_params = {k: v for k, v in params.items()}
                test_params[key] = ["http://127.0.0.1:1/"]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                status, _, text = await self._fetch_text(test_url)
                tested += 1
                if status == 0:
                    continue
                lower = text.lower()
                if any(marker in lower for marker in error_markers):
                    vulnerabilities.append({
                        'id': 'ssrf-heuristic',
                        'type': 'SSRF',
                        'severity': 'High',
                        'description': f'Potential SSRF via parameter: {key}',
                        'url': test_url,
                        'details': 'Response indicates backend attempted to fetch the supplied URL'
                    })
        return vulnerabilities


    async def check_xxe_endpoints(self, urls: List[str]) -> List[Dict]:
        """Probe for XML parser responses that may indicate XXE surface."""
        vulnerabilities = []
        xml_payload = """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>"""
        xml_headers = {'Content-Type': 'application/xml'}
        tested = 0

        for target in urls:
            parsed = urlparse(target)
            if any(suffix in parsed.path.lower() for suffix in ['.xml', '/soap', '/api/xml']):
                candidate = target
            else:
                continue

            if tested >= 10:
                break
            status, _, text = await self._post_text(candidate, xml_payload, headers=xml_headers)
            tested += 1
            if status == 0:
                continue
            lower = text.lower()
            if 'doctype' in lower or 'entity' in lower or 'xml' in lower and 'error' in lower:
                vulnerabilities.append({
                    'id': 'xxe-heuristic',
                    'type': 'XXE',
                    'severity': 'High',
                    'description': 'XML parser behavior detected with external entity payload',
                    'url': candidate,
                    'details': 'Endpoint responded with XML/DTD parsing errors'
                })
        return vulnerabilities


    async def check_rest_search_probes(self, base_url: str) -> List[Dict]:
        """Probe common REST search endpoint for SQLi/XSS signals."""
        vulnerabilities = []
        search_url = urljoin(base_url.rstrip("/") + "/", "rest/products/search")

        # SQLi probe
        sqli_url = f"{search_url}?q=1%27"
        status, _, text = await self._fetch_text(sqli_url)
        if status >= 500 and text:
            lower = text.lower()
            if "sqlite" in lower or "sql" in lower or "syntax error" in lower:
                vulnerabilities.append({
                    'id': 'sqli-rest-search',
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'description': 'Potential SQL injection on /rest/products/search',
                    'url': sqli_url,
                    'details': 'REST search endpoint returned SQL error patterns'
                })

        # XSS probe
        xss_payload = "<script>dawnxss</script>"
        xss_url = f"{search_url}?q={xss_payload}"
        status, _, text = await self._fetch_text(xss_url)
        if status < 400 and xss_payload in text:
            vulnerabilities.append({
                'id': 'xss-rest-search',
                'type': 'Reflected XSS',
                'severity': 'High',
                'description': 'Potential reflected XSS on /rest/products/search',
                'url': xss_url,
                'details': 'XSS payload appears in response body'
            })

        return vulnerabilities


    async def check_file_upload_forms(self, urls: List[str]) -> List[Dict]:
        """Detect forms that allow file uploads"""
        vulnerabilities = []
        for target in urls:
            status, _, text = await self._fetch_text(target)
            if status >= 400 or not text:
                continue

            for match in re.finditer(r'<form([^>]*)>(.*?)</form>', text, flags=re.IGNORECASE | re.DOTALL):
                attrs = match.group(1).lower()
                body = match.group(2)
                if 'multipart/form-data' in attrs and 'type="file"' in body.lower():
                    vulnerabilities.append({
                        'id': 'file-upload-form',
                        'type': 'File Upload Endpoint',
                        'severity': 'Low',
                        'description': 'File upload form detected',
                        'url': target,
                        'details': 'File upload endpoints require strict validation and storage controls'
                    })
                    break
        return vulnerabilities


    async def check_access_control(self, base_url: str) -> List[Dict]:
        """Check for potentially exposed admin paths"""
        vulnerabilities = []
        common_paths = [
            '/admin',
            '/administrator',
            '/administration',
            '/console',
            '/manage',
            '/management',
            '/api/admin',
            '/api/administration'
        ]

        for path in common_paths:
            test_url = base_url.rstrip('/') + path
            status, _, text = await self._fetch_text(test_url)
            if status == 200 and text:
                vulnerabilities.append({
                    'id': f'access-control-{path.replace("/", "")}',
                    'type': 'Access Control Exposure',
                    'severity': 'Low',
                    'description': f'Potentially exposed admin path: {path}',
                    'url': test_url,
                    'details': 'Administrative paths should require authentication and authorization'
                })
                break
        return vulnerabilities


    async def check_common_vulnerabilities(self, url: str) -> List[Dict]:
        """Check for common web vulnerabilities"""
        vulnerabilities = []
        
        # Check for common vulnerability patterns
        try:
            # Check for directory listing
            dir_listing_vulns = await self._check_directory_listing(url)
            vulnerabilities.extend(dir_listing_vulns)
            
            # Check for common misconfigurations
            config_vulns = await self._check_common_configs(url)
            vulnerabilities.extend(config_vulns)
            
        except Exception as e:
            logger.warning(f"Common vulnerability check failed for {url}: {e}")
        
        return vulnerabilities


    async def _check_directory_listing(self, url: str) -> List[Dict]:
        """Check for directory listing vulnerabilities"""
        vulnerabilities = []
        
        # Common paths that might expose directory listings
        common_paths = [
            '/images/',
            '/assets/',
            '/static/',
            '/upload/',
            '/files/',
            '/admin/',
            '/backup/',
            '/config/',
            '/logs/'
        ]
        
        for path in common_paths:
            test_url = url.rstrip('/') + path
            
            try:
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Simple heuristic to detect directory listing
                        if any(keyword in content.lower() for keyword in ['index of', 'parent directory', 'last modified']):
                            vulnerabilities.append({
                                'id': f'dir-listing-{path.replace("/", "")}',
                                'type': 'Directory Listing',
                                'severity': 'Medium',
                                'description': f'Directory listing enabled for {path}',
                                'url': test_url,
                                'details': f'The directory {path} is publicly accessible and shows file listings'
                            })
                            break  # Found one, no need to check others
                            
            except Exception:
                # URL might not exist, which is fine
                continue
                
        return vulnerabilities


    async def _check_common_configs(self, url: str) -> List[Dict]:
        """Check for common configuration files"""
        vulnerabilities = []
        
        # Common config files that shouldn't be exposed
        config_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/config',
            '/.svn/entries',
            '/.htaccess',
            '/web.config',
            '/.env',
            '/config.php',
            '/database.yml',
            '/settings.py'
        ]
        
        sensitive_patterns = [
            'password',
            'secret',
            'key',
            'token',
            'username',
            'api_key',
            'db_password'
        ]
        
        for file_path in config_files:
            test_url = url.rstrip('/') + file_path
            
            try:
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if the file contains sensitive information
                        content_lower = content.lower()
                        found_sensitive = [pattern for pattern in sensitive_patterns if pattern in content_lower]
                        
                        if found_sensitive:
                            vulnerabilities.append({
                                'id': f'sensitive-config-{file_path.replace("/", "").replace(".", "")}',
                                'type': 'Sensitive Configuration Exposure',
                                'severity': 'High',
                                'description': f'Sensitive data exposed in {file_path}',
                                'url': test_url,
                                'details': f'The file {file_path} contains sensitive information: {", ".join(found_sensitive)}'
                            })
                            
            except Exception:
                # URL might not exist, which is fine
                continue
                
        return vulnerabilities


async def main():
    """Main function to run the scanner"""
    if len(sys.argv) != 2:
        print("Usage: python worker.py <url_to_scan>")
        sys.exit(1)
    
    url = sys.argv[1]
    
    async with VulnerabilityScanner() as scanner:
        result = await scanner.scan_url(url)
        
        # Print result as JSON
        result_dict = {
            'url': result.url,
            'vulnerabilities': result.vulnerabilities,
            'summary': result.summary,
            'timestamp': result.timestamp,
            'scan_duration': result.scan_duration
        }
        
        print(json.dumps(result_dict, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
