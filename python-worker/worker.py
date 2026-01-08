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
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import subprocess
import socket
from urllib.parse import urlparse

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
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()


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
            
            # Perform various security checks
            vulnerabilities.extend(await self.check_ssl_security(url))
            vulnerabilities.extend(await self.check_headers_security(url))
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
                    
                if 'X-Content-Type-Options' not in headers:
                    missing_headers.append('X-Content-Type-Options (MIME-type confusion)')
                    
                if 'X-XSS-Protection' not in headers:
                    missing_headers.append('X-XSS-Protection (cross-site scripting)')
                    
                if 'Strict-Transport-Security' not in headers and url.startswith('https'):
                    missing_headers.append('Strict-Transport-Security (HSTS)')
                    
                if 'Content-Security-Policy' not in headers:
                    missing_headers.append('Content-Security-Policy (script injection)')
                
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