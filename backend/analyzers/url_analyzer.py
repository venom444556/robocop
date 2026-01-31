"""URL analyzer for expanding, categorizing, and fetching content from URLs."""

import re
import socket
import ipaddress
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import asyncio

logger = logging.getLogger(__name__)

# Maximum content size to fetch (10MB)
MAX_CONTENT_SIZE = 10 * 1024 * 1024

# Private/internal IP ranges to block (SSRF protection)
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local
    ipaddress.ip_network('::1/128'),  # IPv6 localhost
    ipaddress.ip_network('fc00::/7'),  # IPv6 private
    ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
]


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address is internal/private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_safe_url(url: str) -> Tuple[bool, str]:
    """
    Check if a URL is safe to fetch (not pointing to internal resources).

    Returns:
        Tuple of (is_safe, error_message)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]  # Remove port if present

        # Block non-http(s) schemes
        if parsed.scheme not in ('http', 'https'):
            return False, f"Blocked scheme: {parsed.scheme}"

        # Block localhost variants
        if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            return False, "Blocked: localhost"

        # Try to resolve hostname and check IP
        try:
            ip = socket.gethostbyname(hostname)
            if is_internal_ip(ip):
                return False, f"Blocked: internal IP {ip}"
        except socket.gaierror:
            # Can't resolve - might be intentional for malware analysis
            # Log but allow (the request will fail anyway)
            logger.warning(f"Could not resolve hostname: {hostname}")

        return True, ""
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


class URLAnalyzer:
    """Analyze URLs for malicious indicators and fetch content."""

    # Script file extensions to auto-fetch
    SCRIPT_EXTENSIONS = {
        '.ps1': 'powershell',
        '.psm1': 'powershell',
        '.js': 'javascript',
        '.vbs': 'vbscript',
        '.vbe': 'vbscript',
        '.bat': 'batch',
        '.cmd': 'batch',
        '.py': 'python',
        '.sh': 'bash',
        '.hta': 'hta',
    }

    # URL shortener domains
    SHORTENER_DOMAINS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im',
        'cli.gs', 'short.to', 'budurl.com', 'ping.fm',
        'post.ly', 'just.as', 'bkite.com', 'snipr.com',
        'fic.kr', 'loopt.us', 'doiop.com', 'short.ie',
        'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'rb.gy'
    }

    def __init__(self):
        """Initialize the URL analyzer."""
        self.redirect_chain = []
        self.max_redirects = 10

    async def analyze(self, url: str, allow_internal: bool = False) -> Dict:
        """
        Perform comprehensive URL analysis.

        Args:
            url: URL to analyze
            allow_internal: If True, allow internal IPs (use with caution)

        Returns:
            Dictionary with analysis results
        """
        import httpx

        results = {
            "original_url": url,
            "effective_url": url,
            "redirect_chain": [],
            "is_shortened": False,
            "domain_info": {},
            "content_type": None,
            "is_script": False,
            "fetched_script": None,
            "content_filename": None,
            "categorization": {},
            "errors": []
        }

        # Parse original URL
        parsed = urlparse(url)
        results["domain_info"] = {
            "scheme": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query
        }

        # SSRF protection: Check if URL is safe to fetch
        if not allow_internal:
            is_safe, error_msg = is_safe_url(url)
            if not is_safe:
                results["errors"].append(f"SSRF protection: {error_msg}")
                logger.warning(f"Blocked URL fetch due to SSRF protection: {url} - {error_msg}")
                return results

        # Check if it's a shortened URL
        domain = parsed.netloc.lower()
        results["is_shortened"] = any(
            shortener in domain for shortener in self.SHORTENER_DOMAINS
        )

        # Expand URL and follow redirects
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=self.max_redirects,
                timeout=30.0,
                verify=False  # For malware analysis, we may encounter bad certs
            ) as client:
                response = await client.get(url)

                # Check content length before processing
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_CONTENT_SIZE:
                    results["errors"].append(f"Content too large: {content_length} bytes (max: {MAX_CONTENT_SIZE})")
                    return results

                # Build redirect chain from history
                for resp in response.history:
                    # SSRF check on redirects too
                    if not allow_internal:
                        redirect_safe, redirect_err = is_safe_url(str(resp.url))
                        if not redirect_safe:
                            results["errors"].append(f"Redirect blocked: {redirect_err}")
                            return results
                    results["redirect_chain"].append({
                        "url": str(resp.url),
                        "status_code": resp.status_code
                    })

                results["redirect_chain"].append({
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "final": True
                })

                results["effective_url"] = str(response.url)
                results["content_type"] = response.headers.get("content-type", "")
                results["status_code"] = response.status_code

                # Check if content is a script
                content_type = results["content_type"].lower()
                effective_path = urlparse(str(response.url)).path.lower()

                # Determine if it's a script by extension or content-type
                is_script = False
                script_type = None

                for ext, stype in self.SCRIPT_EXTENSIONS.items():
                    if effective_path.endswith(ext):
                        is_script = True
                        script_type = stype
                        results["content_filename"] = effective_path.split('/')[-1]
                        break

                # Also check content-type
                if not is_script:
                    script_content_types = [
                        'text/plain', 'application/javascript', 'text/javascript',
                        'application/x-powershell', 'text/x-python', 'text/x-sh'
                    ]
                    if any(ct in content_type for ct in script_content_types):
                        # Check content for script indicators
                        text_content = response.text[:5000]  # Sample first 5KB
                        if self._looks_like_script(text_content):
                            is_script = True
                            script_type = self._detect_script_type(text_content)
                            results["content_filename"] = "downloaded_script"

                results["is_script"] = is_script

                # Fetch script content if it's a script (with size limit)
                if is_script:
                    content = response.text
                    if len(content) > MAX_CONTENT_SIZE:
                        results["errors"].append(f"Script content too large, truncated to {MAX_CONTENT_SIZE} bytes")
                        content = content[:MAX_CONTENT_SIZE]
                    results["fetched_script"] = content
                    results["script_type"] = script_type
                    results["content_size"] = len(content)

        except httpx.TooManyRedirects:
            results["errors"].append("Too many redirects")
        except httpx.TimeoutException:
            results["errors"].append("Request timed out")
        except httpx.RequestError as e:
            results["errors"].append(f"Request error: {str(e)}")
        except Exception as e:
            results["errors"].append(f"Unexpected error: {str(e)}")

        return results

    def _looks_like_script(self, content: str) -> bool:
        """Check if content looks like a script."""
        script_indicators = [
            # PowerShell
            r'\$\w+\s*=', r'function\s+\w+', r'param\s*\(', r'Invoke-',
            # JavaScript
            r'function\s*\(', r'var\s+\w+\s*=', r'const\s+\w+\s*=', r'let\s+\w+\s*=',
            # VBScript
            r'Dim\s+\w+', r'Sub\s+\w+', r'CreateObject\s*\(',
            # Batch
            r'@echo\s+off', r'set\s+\w+=', r'goto\s+:',
            # Python
            r'import\s+\w+', r'def\s+\w+\s*\(', r'class\s+\w+',
            # Bash
            r'#!/bin/(?:ba)?sh', r'if\s+\[\s*', r'for\s+\w+\s+in',
        ]

        for pattern in script_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _detect_script_type(self, content: str) -> str:
        """Detect script type from content."""
        content_lower = content.lower()

        if any(ind in content_lower for ind in ['$psversiontable', 'invoke-', 'new-object']):
            return "powershell"
        elif any(ind in content_lower for ind in ['wscript.', 'createobject(']):
            return "vbscript"
        elif any(ind in content_lower for ind in ['function(', 'document.', 'window.']):
            return "javascript"
        elif any(ind in content_lower for ind in ['@echo off', 'goto ', '%~']):
            return "batch"
        elif any(ind in content_lower for ind in ['import ', 'def ', 'class ']):
            return "python"
        elif '#!/bin/' in content_lower:
            return "bash"

        return "unknown"

    async def expand_shortened_url(self, url: str) -> Dict:
        """
        Expand a shortened URL using Unshorten.me API.

        Args:
            url: Shortened URL to expand

        Returns:
            Dictionary with expansion results
        """
        import httpx

        results = {
            "original_url": url,
            "expanded_url": None,
            "service": "unshorten.me",
            "error": None
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"https://unshorten.me/json/{url}"
                )
                data = response.json()

                if data.get("success"):
                    results["expanded_url"] = data.get("resolved_url")
                else:
                    results["error"] = data.get("error", "Unknown error")

        except Exception as e:
            results["error"] = str(e)

        return results

    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        url_pattern = re.compile(
            r'https?://[^\s<>"\']+|'
            r'hxxps?://[^\s<>"\']+|'
            r'ftp://[^\s<>"\']+',
            re.IGNORECASE
        )

        urls = url_pattern.findall(text)

        # Clean and normalize URLs
        cleaned_urls = []
        for url in urls:
            # Handle defanged URLs
            url = url.replace('hxxp', 'http')
            url = url.replace('[.]', '.')
            url = url.replace('[dot]', '.')
            # Remove trailing punctuation
            url = url.rstrip('.,;:\'\")')
            if len(url) > 10:
                cleaned_urls.append(url)

        return list(set(cleaned_urls))

    def assess_url_risk(self, url: str) -> Dict:
        """
        Perform basic risk assessment on a URL.

        Args:
            url: URL to assess

        Returns:
            Dictionary with risk indicators
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        risk_indicators = []
        risk_score = 0

        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_indicators.append("Suspicious TLD")
            risk_score += 20

        # Check for IP address as host
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.match(domain):
            risk_indicators.append("IP address as hostname")
            risk_score += 30

        # Check for suspicious file extensions
        dangerous_extensions = ['.exe', '.dll', '.scr', '.pif', '.com', '.hta', '.vbs', '.js', '.ps1']
        if any(path.endswith(ext) for ext in dangerous_extensions):
            risk_indicators.append("Potentially dangerous file extension")
            risk_score += 25

        # Check for URL shortener
        if any(shortener in domain for shortener in self.SHORTENER_DOMAINS):
            risk_indicators.append("URL shortener")
            risk_score += 15

        # Check for suspicious patterns in path
        suspicious_patterns = ['download', 'update', 'flash', 'plugin', 'security', 'invoice']
        if any(pattern in path for pattern in suspicious_patterns):
            risk_indicators.append("Suspicious path pattern")
            risk_score += 10

        # Check for very long URLs (often used in phishing)
        if len(url) > 200:
            risk_indicators.append("Unusually long URL")
            risk_score += 15

        # Check for many subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            risk_indicators.append("Many subdomains")
            risk_score += 20

        # Check for @ in URL (can be used to obscure real destination)
        if '@' in url:
            risk_indicators.append("Contains @ symbol (potential URL obfuscation)")
            risk_score += 40

        # Determine risk level
        if risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        elif risk_score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"

        return {
            "url": url,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_indicators": risk_indicators
        }
