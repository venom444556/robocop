"""IOC (Indicators of Compromise) extraction from text content."""

import re
from typing import Dict, List, Set
import hashlib


class IOCExtractor:
    """Extract various IOCs from text content using regex patterns."""

    def __init__(self):
        """Initialize IOC patterns."""
        # IP address patterns (IPv4)
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        # Domain pattern (more permissive)
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'(?:com|net|org|edu|gov|mil|biz|info|io|co|us|uk|de|fr|ru|cn|'
            r'xyz|top|pw|tk|ml|ga|cf|gq|cc|tv|ws|me|ly|to|sh|su|onion)\b',
            re.IGNORECASE
        )

        # URL pattern
        self.url_pattern = re.compile(
            r'https?://[^\s<>"\']+|'
            r'hxxps?://[^\s<>"\']+|'  # Defanged URLs
            r'ftp://[^\s<>"\']+',
            re.IGNORECASE
        )

        # Hash patterns
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

        # Email pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )

        # Registry key pattern (Windows)
        self.registry_pattern = re.compile(
            r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
            r'HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)'
            r'\\[^\s"\'<>]+',
            re.IGNORECASE
        )

        # File path patterns
        self.windows_path_pattern = re.compile(
            r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
            re.IGNORECASE
        )
        self.unix_path_pattern = re.compile(
            r'/(?:[^/\0\s]+/)*[^/\0\s]+'
        )

        # Mutex pattern (common malware mutexes)
        self.mutex_pattern = re.compile(
            r'(?:Global\\|Local\\)?[A-Za-z0-9_-]{8,}(?:Mutex|mtx|MUTEX)?',
            re.IGNORECASE
        )

        # User-Agent pattern
        self.user_agent_pattern = re.compile(
            r'Mozilla/[\d.]+\s*\([^)]+\)[^\r\n]*',
            re.IGNORECASE
        )

        # Bitcoin address pattern
        self.bitcoin_pattern = re.compile(
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|'
            r'\bbc1[a-z0-9]{39,59}\b'
        )

        # Private IP ranges to exclude
        self.private_ip_ranges = [
            re.compile(r'^10\.'),
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^127\.'),
            re.compile(r'^0\.'),
            re.compile(r'^169\.254\.'),
        ]

        # Common false positive domains
        self.fp_domains = {
            'microsoft.com', 'windows.com', 'google.com', 'github.com',
            'example.com', 'localhost', 'test.com', 'schema.org',
            'w3.org', 'xmlsoap.org', 'schemas.microsoft.com'
        }

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private/reserved."""
        for pattern in self.private_ip_ranges:
            if pattern.match(ip):
                return True
        return False

    def _clean_url(self, url: str) -> str:
        """Clean and normalize URL."""
        # Handle defanged URLs
        url = url.replace('hxxp', 'http')
        url = url.replace('[.]', '.')
        url = url.replace('[dot]', '.')
        url = url.replace('[:]', ':')
        # Remove trailing punctuation
        url = url.rstrip('.,;:\'\")')
        return url

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid and not a false positive."""
        domain_lower = domain.lower()
        # Check against known false positives
        if domain_lower in self.fp_domains:
            return False
        # Check if it's just a TLD
        if '.' not in domain:
            return False
        # Check minimum length
        if len(domain) < 4:
            return False
        return True

    def extract(self, content: str, include_private_ips: bool = False) -> Dict[str, List[str]]:
        """
        Extract all IOCs from the given content.

        Args:
            content: Text content to analyze
            include_private_ips: Whether to include private/reserved IP addresses

        Returns:
            Dictionary mapping IOC types to lists of extracted values
        """
        iocs: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash_md5": set(),
            "hash_sha1": set(),
            "hash_sha256": set(),
            "email": set(),
            "registry_key": set(),
            "file_path": set(),
            "mutex": set(),
            "filename": set(),
            "user_agent": set(),
        }

        # Extract URLs first (to avoid extracting domains from URLs separately)
        urls = self.url_pattern.findall(content)
        for url in urls:
            cleaned = self._clean_url(url)
            if len(cleaned) > 10:  # Minimum URL length
                iocs["url"].add(cleaned)

        # Extract IPs
        ips = self.ipv4_pattern.findall(content)
        for ip in ips:
            if include_private_ips or not self._is_private_ip(ip):
                iocs["ip"].add(ip)

        # Extract domains (exclude those already in URLs)
        domains = self.domain_pattern.findall(content)
        url_content = ' '.join(iocs["url"])
        for domain in domains:
            if self._is_valid_domain(domain) and domain.lower() not in url_content.lower():
                iocs["domain"].add(domain.lower())

        # Extract hashes
        # Check SHA256 first (longest)
        sha256_matches = self.sha256_pattern.findall(content)
        for h in sha256_matches:
            iocs["hash_sha256"].add(h.lower())

        # SHA1 (avoid matching parts of SHA256)
        sha1_matches = self.sha1_pattern.findall(content)
        for h in sha1_matches:
            if h.lower() not in [s[:40] for s in iocs["hash_sha256"]]:
                iocs["hash_sha1"].add(h.lower())

        # MD5 (avoid matching parts of longer hashes)
        md5_matches = self.md5_pattern.findall(content)
        for h in md5_matches:
            is_part_of_longer = False
            for sha1 in iocs["hash_sha1"]:
                if h.lower() in sha1:
                    is_part_of_longer = True
                    break
            for sha256 in iocs["hash_sha256"]:
                if h.lower() in sha256:
                    is_part_of_longer = True
                    break
            if not is_part_of_longer:
                iocs["hash_md5"].add(h.lower())

        # Extract emails
        emails = self.email_pattern.findall(content)
        for email in emails:
            iocs["email"].add(email.lower())

        # Extract registry keys
        reg_keys = self.registry_pattern.findall(content)
        for key in reg_keys:
            iocs["registry_key"].add(key)

        # Extract user agents
        user_agents = self.user_agent_pattern.findall(content)
        for ua in user_agents:
            if len(ua) > 20:  # Minimum user agent length
                iocs["user_agent"].add(ua.strip())

        # Extract file paths
        # Exclude common non-IOC paths (schema URLs, XML namespaces, etc.)
        fp_exclusions = {'C:\\Windows', 'C:\\Program Files', 'C:\\Users\\Public'}
        win_paths = self.windows_path_pattern.findall(content)
        for path in win_paths:
            if len(path) > 5 and not any(path.startswith(ex) for ex in fp_exclusions):
                iocs["file_path"].add(path)
        unix_paths = self.unix_path_pattern.findall(content)
        for path in unix_paths:
            # Filter out common false positives (URLs already captured, short paths, XML/HTML)
            if (len(path) > 5 and not path.startswith('//')
                    and not path.startswith('/>')
                    and not path.endswith('.html')
                    and path.count('/') >= 2):
                iocs["file_path"].add(path)

        # Extract mutexes (look for mutex creation context)
        mutex_contexts = [
            re.compile(r'(?:CreateMutex|OpenMutex)\w*\s*\([^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'(?:Global\\|Local\\)([A-Za-z0-9_\-]{4,})', re.IGNORECASE),
            re.compile(r'mutex[_\s]*(?:name|=|:)\s*["\']([^"\']+)["\']', re.IGNORECASE),
        ]
        for pattern in mutex_contexts:
            for m in pattern.findall(content):
                if len(m) >= 4:
                    iocs["mutex"].add(m)

        # Convert sets to lists
        return {k: list(v) for k, v in iocs.items() if v}

    def extract_from_script(self, content: str, script_type: str = "unknown") -> Dict[str, List[str]]:
        """
        Extract IOCs with script-specific handling.

        Args:
            content: Script content
            script_type: Type of script (powershell, javascript, vbscript, etc.)

        Returns:
            Dictionary of extracted IOCs
        """
        iocs = self.extract(content)

        # Script-specific patterns
        if script_type.lower() in ["powershell", "ps1"]:
            # PowerShell specific patterns
            invoke_webrequest = re.findall(
                r'(?:Invoke-WebRequest|iwr|wget|curl)\s+["\']?([^"\'>\s]+)',
                content, re.IGNORECASE
            )
            for url in invoke_webrequest:
                cleaned = self._clean_url(url)
                if cleaned not in iocs.get("url", []):
                    iocs.setdefault("url", []).append(cleaned)

            # DownloadString/DownloadFile patterns
            download_patterns = re.findall(
                r'\.(?:DownloadString|DownloadFile|DownloadData)\(["\']([^"\']+)',
                content, re.IGNORECASE
            )
            for url in download_patterns:
                cleaned = self._clean_url(url)
                if cleaned not in iocs.get("url", []):
                    iocs.setdefault("url", []).append(cleaned)

        elif script_type.lower() in ["javascript", "js"]:
            # JavaScript specific patterns
            fetch_xhr = re.findall(
                r'(?:fetch|XMLHttpRequest|\.open)\s*\(["\'](?:GET|POST)?\s*["\']?\s*,?\s*["\']?([^"\'>\s)]+)',
                content, re.IGNORECASE
            )
            for url in fetch_xhr:
                cleaned = self._clean_url(url)
                if cleaned not in iocs.get("url", []):
                    iocs.setdefault("url", []).append(cleaned)

        elif script_type.lower() in ["vbscript", "vbs"]:
            # VBScript specific patterns
            msxml = re.findall(
                r'\.Open\s+["\'](?:GET|POST)["\'],\s*["\']([^"\']+)',
                content, re.IGNORECASE
            )
            for url in msxml:
                cleaned = self._clean_url(url)
                if cleaned not in iocs.get("url", []):
                    iocs.setdefault("url", []).append(cleaned)

        return iocs

    def defang(self, ioc: str, ioc_type: str = "auto") -> str:
        """
        Defang an IOC for safe sharing.

        Args:
            ioc: The IOC to defang
            ioc_type: Type of IOC (ip, domain, url, email, auto)

        Returns:
            Defanged IOC string
        """
        if ioc_type == "auto":
            if self.ipv4_pattern.match(ioc):
                ioc_type = "ip"
            elif self.url_pattern.match(ioc):
                ioc_type = "url"
            elif self.email_pattern.match(ioc):
                ioc_type = "email"
            else:
                ioc_type = "domain"

        if ioc_type == "ip":
            return ioc.replace('.', '[.]')
        elif ioc_type == "url":
            return ioc.replace('http', 'hxxp').replace('.', '[.]')
        elif ioc_type == "domain":
            return ioc.replace('.', '[.]')
        elif ioc_type == "email":
            return ioc.replace('@', '[@]').replace('.', '[.]')
        return ioc

    def refang(self, ioc: str) -> str:
        """
        Refang a defanged IOC.

        Args:
            ioc: Defanged IOC

        Returns:
            Original IOC string
        """
        return (ioc
                .replace('hxxp', 'http')
                .replace('[.]', '.')
                .replace('[:]', ':')
                .replace('[@]', '@')
                .replace('[dot]', '.'))
