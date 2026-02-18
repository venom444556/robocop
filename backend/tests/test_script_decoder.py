"""Tests for the script decoder / deobfuscation engine."""

import sys
import os
import base64
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.script_decoder import ScriptDecoder, DecodingResult


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def decoder():
    """Provide a fresh ScriptDecoder instance."""
    return ScriptDecoder()


# ===================================================================
# Base64 Decoding
# ===================================================================

class TestBase64Decoding:
    """Tests for Base64 block detection and decoding."""

    def test_base64_in_convert_call(self, decoder):
        """Base64 wrapped in [Convert]::FromBase64String() should be decoded."""
        plaintext = "Invoke-Expression (Get-Content malware.ps1)"
        encoded = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        content = f'$decoded = [Convert]::FromBase64String("{encoded}")'
        result = decoder.decode(content)
        assert result["decoded"] is True
        assert "base64" in result["techniques_found"]
        assert plaintext in result["decoded_content"]

    def test_base64_in_quoted_string(self, decoder):
        """A long Base64 string inside quotes should be detected."""
        plaintext = "This is a secret payload for testing base64 decoding functionality"
        encoded = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        # Must be >= 40 chars for the generic pattern
        assert len(encoded) >= 40
        content = f'$data = "{encoded}"'
        result = decoder.decode(content)
        assert result["decoded"] is True
        assert plaintext in result["decoded_content"]

    def test_short_base64_not_decoded(self, decoder):
        """Base64 strings shorter than 40 characters should not trigger decoding."""
        short_b64 = base64.b64encode(b"hi").decode("ascii")  # "aGk="
        content = f'$x = "{short_b64}"'
        result = decoder.decode(content)
        assert result["decoded"] is False

    def test_base64_encoding_layer_info(self, decoder):
        """The encoding_layers list should contain metadata about the base64 decode."""
        plaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        encoded = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        content = f'[System.Convert]::FromBase64String("{encoded}")'
        result = decoder.decode(content)
        assert len(result["encoding_layers"]) >= 1
        layer = result["encoding_layers"][0]
        assert layer["type"] == "base64"
        assert "confidence" in layer


# ===================================================================
# PowerShell Encoded Command
# ===================================================================

class TestPowerShellEncodedCommand:
    """Tests for PowerShell -EncodedCommand / -enc decoding."""

    def _encode_ps(self, text: str) -> str:
        """Encode text as PowerShell would (UTF-16LE then Base64)."""
        return base64.b64encode(text.encode("utf-16-le")).decode("ascii")

    def test_full_encoded_command_flag(self, decoder):
        payload = "Write-Host 'pwned'"
        encoded = self._encode_ps(payload)
        content = f"powershell.exe -EncodedCommand {encoded}"
        result = decoder.decode(content)
        assert result["decoded"] is True
        assert "powershell_encoded_command" in result["techniques_found"]
        assert payload in result["decoded_content"]

    def test_short_enc_flag(self, decoder):
        payload = "Get-Process | Stop-Process"
        encoded = self._encode_ps(payload)
        content = f"powershell -enc {encoded}"
        result = decoder.decode(content)
        assert result["decoded"] is True
        assert payload in result["decoded_content"]

    def test_e_flag_only(self, decoder):
        payload = "net user hacker P@ss /add"
        encoded = self._encode_ps(payload)
        content = f"powershell -e {encoded}"
        result = decoder.decode(content)
        assert result["decoded"] is True
        assert payload in result["decoded_content"]

    def test_encoded_command_confidence(self, decoder):
        """PowerShell encoded commands should have high confidence."""
        payload = "IEX (something)"
        encoded = self._encode_ps(payload)
        content = f"powershell -EncodedCommand {encoded}"
        result = decoder.decode(content)
        assert len(result["encoding_layers"]) >= 1
        assert result["encoding_layers"][0]["confidence"] >= 0.9


# ===================================================================
# Character Array Decoding
# ===================================================================

class TestCharArrayDecoding:
    """Tests for PowerShell [char] array decoding."""

    def test_char_array_sequence(self, decoder):
        """A sequence of [char] codes (without + concatenation) should be decoded."""
        # "Hello" = 72 101 108 108 111
        # Use semicolons instead of + so the ps_pattern (which looks for +)
        # does NOT match and the fallback all_chars path is triggered.
        content = "[char]72; [char]101; [char]108; [char]108; [char]111"
        result = decoder.decode(content)
        # The decoder requires at least 5 chars in sequence
        assert result["decoded"] is True
        assert "Hello" in result["decoded_content"]

    def test_char_array_not_triggered_for_few_chars(self, decoder):
        """Fewer than 5 [char] codes should not trigger decoding."""
        content = "[char]72+[char]101"
        result = decoder.decode(content)
        assert result["decoded"] is False


# ===================================================================
# VBScript Chr() Decoding
# ===================================================================

class TestVBSChrDecoding:
    """Tests for VBScript Chr() encoding."""

    def test_vbs_chr_sequence(self, decoder):
        """Sequence of Chr() calls should be decoded."""
        # "Hello" = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)
        content = 'x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)'
        result = decoder.decode(content)
        assert result["decoded"] is True
        assert "Hello" in result["decoded_content"]

    def test_vbs_chr_with_spaces(self, decoder):
        """Chr calls with varying whitespace should still be decoded."""
        content = 'x = Chr( 72 ) & Chr( 101 ) & Chr( 108 ) & Chr( 108 ) & Chr( 111 )'
        result = decoder.decode(content)
        assert result["decoded"] is True

    def test_vbs_chrw_variant(self, decoder):
        """ChrW variant should also be detected."""
        content = 'x = ChrW(72) & ChrW(101) & ChrW(108) & ChrW(108) & ChrW(111)'
        result = decoder.decode(content)
        assert result["decoded"] is True


# ===================================================================
# JavaScript unescape / URL Encoding
# ===================================================================

class TestJSUnescape:
    """Tests for JavaScript unescape() and URL-encoded strings."""

    def test_unescape_percent_encoded(self, decoder):
        """unescape('%XX') sequences should be URL-decoded."""
        # URL-encode "alert(1)"
        encoded = "%61%6C%65%72%74%28%31%29"
        content = f'var x = unescape("{encoded}")'
        result = decoder.decode(content)
        assert result["decoded"] is True
        # Should find javascript_unescape or url_encoded technique
        techniques = result["techniques_found"]
        assert any(t in techniques for t in ["javascript_unescape", "url_encoded"])


# ===================================================================
# Non-Encoded Content
# ===================================================================

class TestNonEncodedContent:
    """Tests that plain content is not falsely flagged as encoded."""

    def test_plain_powershell_not_decoded(self, decoder):
        content = """
        Get-Process | Where-Object { $_.CPU -gt 50 }
        Write-Host "Normal script"
        """
        result = decoder.decode(content)
        assert result["decoded"] is False
        assert result["decoded_content"] == content
        assert len(result["encoding_layers"]) == 0

    def test_plain_javascript_not_decoded(self, decoder):
        content = """
        function greet(name) {
            console.log("Hello, " + name);
        }
        greet("world");
        """
        result = decoder.decode(content)
        assert result["decoded"] is False

    def test_plain_batch_not_decoded(self, decoder):
        content = """
        @echo off
        set PATH=%PATH%;C:\\tools
        echo Done
        """
        result = decoder.decode(content)
        assert result["decoded"] is False

    def test_empty_content(self, decoder):
        result = decoder.decode("")
        assert result["decoded"] is False
        assert result["decoded_content"] == ""


# ===================================================================
# Mixed Encoding Layers
# ===================================================================

class TestMixedEncodingLayers:
    """Tests for multi-layer encoding (nested obfuscation)."""

    def test_powershell_encoded_with_base64_payload(self, decoder):
        """A PowerShell -enc that, once decoded, reveals another base64 block."""
        inner_payload = "Write-Host 'final payload that is long enough to be detected by base64 regex'"
        inner_b64 = base64.b64encode(inner_payload.encode("utf-8")).decode("ascii")
        # The first layer is the PowerShell encoded command
        ps_layer_content = f'$x = [Convert]::FromBase64String("{inner_b64}")'
        ps_encoded = base64.b64encode(ps_layer_content.encode("utf-16-le")).decode("ascii")
        content = f"powershell -enc {ps_encoded}"

        result = decoder.decode(content)
        assert result["decoded"] is True
        assert result["recursion_depth"] >= 1
        # The techniques should include powershell_encoded_command
        assert "powershell_encoded_command" in result["techniques_found"]

    def test_max_recursion_respected(self):
        """The decoder should stop after max_recursion layers."""
        decoder = ScriptDecoder(max_recursion=2)
        # Build 3 layers of base64 (only 2 should be decoded)
        payload = "This is the innermost layer of encoding for a deep test"
        for _ in range(3):
            encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
            payload = f'[Convert]::FromBase64String("{encoded}")'

        result = decoder.decode(payload)
        assert result["recursion_depth"] <= 2


# ===================================================================
# File Extension Context
# ===================================================================

class TestFileExtensionContext:
    """Tests that filename context is passed through correctly."""

    def test_ps1_filename(self, decoder):
        """Decoding with a .ps1 filename should work."""
        payload = "Get-Service | Stop-Service -Force"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
        content = f"powershell -enc {encoded}"
        result = decoder.decode(content, filename="malware.ps1")
        assert result["decoded"] is True

    def test_js_filename(self, decoder):
        """Decoding with a .js filename should work."""
        encoded = "%61%6C%65%72%74%28%31%29"
        content = f'var x = unescape("{encoded}")'
        result = decoder.decode(content, filename="obfuscated.js")
        assert result["decoded"] is True

    def test_vbs_filename(self, decoder):
        """Decoding with a .vbs filename should work."""
        content = 'x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)'
        result = decoder.decode(content, filename="dropper.vbs")
        assert result["decoded"] is True

    def test_bat_filename(self, decoder):
        """Plain batch file should not be decoded."""
        content = "@echo off\ndir C:\\"
        result = decoder.decode(content, filename="script.bat")
        assert result["decoded"] is False


# ===================================================================
# Encoding Type Detection
# ===================================================================

class TestEncodingTypeDetection:
    """Tests for the detect_encoding_type method."""

    def test_detect_powershell_encoded_command(self, decoder):
        content = "powershell -enc AAABBBCCC"
        detected = decoder.detect_encoding_type(content)
        assert "powershell_encoded_command" in detected

    def test_detect_base64(self, decoder):
        content = '[Convert]::FromBase64String("AAAA")'
        detected = decoder.detect_encoding_type(content)
        assert "base64" in detected

    def test_detect_char_array(self, decoder):
        content = "[char]72 + [char]101"
        detected = decoder.detect_encoding_type(content)
        assert "char_array" in detected

    def test_detect_vbscript_chr(self, decoder):
        content = "Chr(65) & Chr(66)"
        detected = decoder.detect_encoding_type(content)
        assert "vbscript_chr" in detected

    def test_detect_javascript_unescape(self, decoder):
        content = 'unescape("%41")'
        detected = decoder.detect_encoding_type(content)
        assert "javascript_unescape" in detected

    def test_detect_compression(self, decoder):
        content = "IO.Compression.GzipStream"
        detected = decoder.detect_encoding_type(content)
        assert "compression" in detected

    def test_detect_xor(self, decoder):
        content = "$x -bxor 42"
        detected = decoder.detect_encoding_type(content)
        assert "xor" in detected

    def test_detect_nothing_on_plain_text(self, decoder):
        content = "This is a normal sentence."
        detected = decoder.detect_encoding_type(content)
        assert detected == []
