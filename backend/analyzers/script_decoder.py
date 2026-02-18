"""Script decoder for various encoding/obfuscation techniques."""

import base64
import logging
import re
import zlib
import codecs
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DecodingResult:
    """Result of a decoding operation."""
    encoding_type: str
    original: str
    decoded: str
    confidence: float
    nested: Optional['DecodingResult'] = None


class ScriptDecoder:
    """Decode encoded and obfuscated scripts."""

    def __init__(self, max_recursion: int = 5):
        """Initialize the decoder."""
        self.max_recursion = max_recursion

    def decode(self, content: str, filename: str = "") -> Dict:
        """
        Decode encoded content, handling multiple layers of encoding.

        Args:
            content: The script content to decode
            filename: Optional filename for context

        Returns:
            Dictionary with decoding results
        """
        results = {
            "decoded": False,
            "original_content": content,
            "decoded_content": content,
            "encoding_layers": [],
            "techniques_found": []
        }

        current_content = content
        recursion_depth = 0

        while recursion_depth < self.max_recursion:
            decoded, layer_info = self._decode_layer(current_content, filename)

            if not decoded or decoded == current_content:
                break

            results["decoded"] = True
            results["encoding_layers"].append(layer_info)
            results["techniques_found"].append(layer_info["type"])
            current_content = decoded
            recursion_depth += 1

        results["decoded_content"] = current_content
        results["recursion_depth"] = recursion_depth

        return results

    def _decode_layer(self, content: str, filename: str) -> Tuple[Optional[str], Dict]:
        """Attempt to decode one layer of encoding."""

        # Check for PowerShell encoded command
        ps_decoded, ps_info = self._decode_powershell_encoded(content)
        if ps_decoded:
            return ps_decoded, ps_info

        # Check for Base64 blocks
        b64_decoded, b64_info = self._decode_base64_blocks(content)
        if b64_decoded:
            return b64_decoded, b64_info

        # Check for character code arrays (PowerShell)
        char_decoded, char_info = self._decode_char_array(content)
        if char_decoded:
            return char_decoded, char_info

        # Check for VBScript Chr() encoding
        vbs_decoded, vbs_info = self._decode_vbs_chr(content)
        if vbs_decoded:
            return vbs_decoded, vbs_info

        # Check for JavaScript unescape
        js_decoded, js_info = self._decode_js_unescape(content)
        if js_decoded:
            return js_decoded, js_info

        # Check for Gzip/Deflate compression
        gz_decoded, gz_info = self._decode_compressed(content)
        if gz_decoded:
            return gz_decoded, gz_info

        # Check for string concatenation obfuscation
        concat_decoded, concat_info = self._decode_string_concat(content)
        if concat_decoded:
            return concat_decoded, concat_info

        # Check for hex encoding
        hex_decoded, hex_info = self._decode_hex(content)
        if hex_decoded:
            return hex_decoded, hex_info

        # Check for ROT13 encoding
        rot13_decoded, rot13_info = self._decode_rot13(content)
        if rot13_decoded:
            return rot13_decoded, rot13_info

        # Check for XOR encoding
        xor_decoded, xor_info = self._decode_xor(content)
        if xor_decoded:
            return xor_decoded, xor_info

        return None, {}

    def _decode_powershell_encoded(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode PowerShell -EncodedCommand payloads."""
        # Pattern for encoded command flag
        pattern = re.compile(
            r'-(?:e(?:nc(?:odedcommand)?)?)\s+([A-Za-z0-9+/=]+)',
            re.IGNORECASE
        )

        matches = pattern.findall(content)
        if not matches:
            return None, {}

        for encoded in matches:
            try:
                # PowerShell uses UTF-16LE encoding
                decoded_bytes = base64.b64decode(encoded)
                decoded = decoded_bytes.decode('utf-16-le', errors='ignore')

                # Replace the encoded portion with decoded
                new_content = content.replace(encoded, f'# DECODED: {decoded}')

                return new_content, {
                    "type": "powershell_encoded_command",
                    "original": encoded[:100] + "..." if len(encoded) > 100 else encoded,
                    "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                    "confidence": 0.95
                }
            except Exception:
                logger.debug("Failed to decode PowerShell encoded command block", exc_info=True)
                continue

        return None, {}

    def _decode_base64_blocks(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode Base64 encoded blocks."""
        # Look for Base64 patterns
        patterns = [
            # PowerShell FromBase64String
            re.compile(r'\[(?:System\.)?Convert\]::FromBase64String\(["\']([A-Za-z0-9+/=]+)["\']\)', re.IGNORECASE),
            # Generic base64 blocks (minimum 40 chars)
            re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),
            # Variable assignment with base64
            re.compile(r'=\s*["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),
        ]

        for pattern in patterns:
            matches = pattern.findall(content)
            for encoded in matches:
                try:
                    decoded_bytes = base64.b64decode(encoded)
                    # Try different encodings
                    for encoding in ['utf-8', 'utf-16-le', 'ascii', 'latin-1']:
                        try:
                            decoded = decoded_bytes.decode(encoding, errors='strict')
                            # Check if decoded content looks like text
                            if self._is_printable(decoded):
                                return decoded, {
                                    "type": "base64",
                                    "original": encoded[:100] + "..." if len(encoded) > 100 else encoded,
                                    "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                                    "encoding": encoding,
                                    "confidence": 0.9
                                }
                        except Exception:
                            logger.debug("Base64 block decode failed with encoding '%s'", encoding)
                            continue
                except Exception:
                    logger.debug("Base64 block decode failed for candidate string", exc_info=True)
                    continue

        return None, {}

    def _decode_char_array(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode character code arrays ([char]72 + [char]101...)."""
        # PowerShell [char] pattern
        ps_pattern = re.compile(
            r'\[char\]\s*(\d+)\s*(?:\+\s*\[char\]\s*(\d+))+',
            re.IGNORECASE
        )

        # Find all char codes in sequence
        char_pattern = re.compile(r'\[char\]\s*(\d+)', re.IGNORECASE)

        matches = ps_pattern.findall(content)
        if not matches:
            # Try finding sequences
            all_chars = char_pattern.findall(content)
            if len(all_chars) >= 5:
                try:
                    decoded = ''.join(chr(int(c)) for c in all_chars if 0 <= int(c) <= 0x10FFFF)
                    if self._is_printable(decoded):
                        return decoded, {
                            "type": "char_array",
                            "char_count": len(all_chars),
                            "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                            "confidence": 0.85
                        }
                except Exception:
                    logger.debug("Failed to decode char array sequence", exc_info=True)
            return None, {}

        return None, {}

    def _decode_vbs_chr(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode VBScript Chr() encoding."""
        # Pattern for Chr() calls
        chr_pattern = re.compile(r'Chr\s*\(\s*(\d+)\s*\)', re.IGNORECASE)
        chr_w_pattern = re.compile(r'ChrW?\s*\(\s*(\d+)\s*\)', re.IGNORECASE)

        all_chars = chr_pattern.findall(content) + chr_w_pattern.findall(content)

        if len(all_chars) >= 5:
            try:
                decoded = ''.join(chr(int(c)) for c in all_chars if 0 <= int(c) <= 0x10FFFF)
                if self._is_printable(decoded):
                    return decoded, {
                        "type": "vbscript_chr",
                        "char_count": len(all_chars),
                        "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                        "confidence": 0.85
                    }
            except Exception:
                logger.debug("Failed to decode VBScript Chr() sequence", exc_info=True)

        return None, {}

    def _decode_js_unescape(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode JavaScript unescape() and %XX sequences."""
        # Pattern for unescape calls
        unescape_pattern = re.compile(
            r'unescape\s*\(\s*["\']([^"\']+)["\']\s*\)',
            re.IGNORECASE
        )

        matches = unescape_pattern.findall(content)
        for encoded in matches:
            try:
                # Decode %XX sequences
                decoded = codecs.decode(encoded, 'unicode_escape')
                if self._is_printable(decoded):
                    return decoded, {
                        "type": "javascript_unescape",
                        "original": encoded[:100] + "..." if len(encoded) > 100 else encoded,
                        "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                        "confidence": 0.9
                    }
            except Exception:
                logger.debug("Failed unicode_escape decode, trying URL decoding", exc_info=True)
                # Try URL decoding
                try:
                    from urllib.parse import unquote
                    decoded = unquote(encoded)
                    if decoded != encoded and self._is_printable(decoded):
                        return decoded, {
                            "type": "url_encoded",
                            "original": encoded[:100],
                            "decoded": decoded[:500],
                            "confidence": 0.85
                        }
                except Exception:
                    logger.debug("URL decoding also failed for JS unescape block", exc_info=True)
                    continue

        return None, {}

    def _decode_compressed(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode Gzip/Deflate compressed content."""
        # Look for compression indicators in PowerShell
        compression_patterns = [
            re.compile(r'IO\.Compression\.(?:Gzip|Deflate)Stream', re.IGNORECASE),
            re.compile(r'FromBase64String.*Decompress', re.IGNORECASE),
        ]

        has_compression = any(p.search(content) for p in compression_patterns)
        if not has_compression:
            return None, {}

        # Find base64 blocks that might be compressed data
        b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{50,}={0,2})["\']')
        matches = b64_pattern.findall(content)

        for encoded in matches:
            try:
                compressed_data = base64.b64decode(encoded)
                # Try gzip
                try:
                    import gzip
                    decompressed = gzip.decompress(compressed_data).decode('utf-8', errors='ignore')
                    if self._is_printable(decompressed):
                        return decompressed, {
                            "type": "gzip_compressed",
                            "compressed_size": len(compressed_data),
                            "decompressed_size": len(decompressed),
                            "decoded": decompressed[:500] + "..." if len(decompressed) > 500 else decompressed,
                            "confidence": 0.9
                        }
                except Exception:
                    logger.debug("Gzip decompression failed for candidate block")

                # Try deflate
                try:
                    decompressed = zlib.decompress(compressed_data, -zlib.MAX_WBITS).decode('utf-8', errors='ignore')
                    if self._is_printable(decompressed):
                        return decompressed, {
                            "type": "deflate_compressed",
                            "compressed_size": len(compressed_data),
                            "decompressed_size": len(decompressed),
                            "decoded": decompressed[:500] + "..." if len(decompressed) > 500 else decompressed,
                            "confidence": 0.9
                        }
                except Exception:
                    logger.debug("Deflate decompression failed for candidate block")

            except Exception:
                logger.debug("Failed to decode compressed content block", exc_info=True)
                continue

        return None, {}

    def _decode_string_concat(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode string concatenation obfuscation."""
        # PowerShell variable-based concatenation
        # $a = "power"; $b = "shell"; iex ($a + $b)
        var_pattern = re.compile(r'\$(\w+)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        vars_found = dict(var_pattern.findall(content))

        if len(vars_found) < 2:
            return None, {}

        # Look for concatenation expressions
        concat_pattern = re.compile(r'\(\s*\$(\w+)(?:\s*\+\s*\$(\w+))+\s*\)')
        concat_matches = concat_pattern.findall(content)

        if concat_matches:
            # This is a simplified approach - full implementation would need expression evaluation
            return None, {}

        # Simple string split detection: "po" + "wer" + "shell"
        split_pattern = re.compile(r'["\']([^"\']{1,10})["\']\s*\+\s*["\']([^"\']{1,10})["\'](?:\s*\+\s*["\']([^"\']{1,10})["\'])*')
        split_matches = split_pattern.findall(content)

        if split_matches:
            for match in split_matches:
                concatenated = ''.join(m for m in match if m)
                if len(concatenated) >= 5:
                    return None, {
                        "type": "string_concatenation",
                        "fragments": list(match),
                        "concatenated": concatenated,
                        "confidence": 0.7
                    }

        return None, {}

    def _decode_hex(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode hex-encoded strings (0x48656C6C6F, \\x48\\x65, etc.)."""
        patterns = [
            # PowerShell hex: 0x48, 0x65, 0x6C, ...
            (re.compile(r'(?:0x[0-9a-fA-F]{2}[,\s]*){5,}'), 'powershell_hex'),
            # Escaped hex: \x48\x65\x6C\x6C\x6F
            (re.compile(r'(?:\\x[0-9a-fA-F]{2}){5,}'), 'escaped_hex'),
            # Continuous hex string assigned to variable (min 20 hex chars = 10 bytes)
            (re.compile(r'["\']([0-9a-fA-F]{20,})["\']'), 'hex_string'),
        ]

        for pattern, hex_type in patterns:
            matches = pattern.findall(content)
            for match in matches:
                try:
                    if hex_type == 'powershell_hex':
                        hex_vals = re.findall(r'0x([0-9a-fA-F]{2})', match)
                        decoded = bytes(int(h, 16) for h in hex_vals).decode('utf-8', errors='ignore')
                    elif hex_type == 'escaped_hex':
                        hex_vals = re.findall(r'\\x([0-9a-fA-F]{2})', match)
                        decoded = bytes(int(h, 16) for h in hex_vals).decode('utf-8', errors='ignore')
                    else:
                        decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')

                    if len(decoded) >= 3 and self._is_printable(decoded):
                        return decoded, {
                            "type": f"hex_encoded ({hex_type})",
                            "original": match[:100] + "..." if len(match) > 100 else match,
                            "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                            "confidence": 0.85
                        }
                except Exception:
                    logger.debug("Hex decode failed for %s pattern", hex_type)
                    continue

        return None, {}

    def _decode_rot13(self, content: str) -> Tuple[Optional[str], Dict]:
        """Decode ROT13-encoded content."""
        # Look for ROT13 indicators
        rot13_indicators = [
            re.compile(r'rot13', re.IGNORECASE),
            re.compile(r'str_rot13', re.IGNORECASE),
            re.compile(r'\.rot13\s*\(', re.IGNORECASE),
        ]

        if not any(p.search(content) for p in rot13_indicators):
            return None, {}

        # Find string arguments near ROT13 calls
        str_patterns = [
            re.compile(r'rot13\s*\(\s*["\']([A-Za-z][^"\']{5,})["\']', re.IGNORECASE),
            re.compile(r'str_rot13\s*\(\s*["\']([A-Za-z][^"\']{5,})["\']', re.IGNORECASE),
        ]

        for pattern in str_patterns:
            matches = pattern.findall(content)
            for encoded in matches:
                decoded = codecs.decode(encoded, 'rot_13')
                new_content = content.replace(encoded, decoded)
                return new_content, {
                    "type": "rot13",
                    "original": encoded[:100] + "..." if len(encoded) > 100 else encoded,
                    "decoded": decoded[:500] + "..." if len(decoded) > 500 else decoded,
                    "confidence": 0.9
                }

        # Fallback: decode all quoted strings that look like ROT13'd code keywords
        # (e.g., "cbjrefuryy" = ROT13 of "powershell")
        known_rot13 = {'cbjrefuryy': 'powershell', 'vak': 'ink', 'rkrp': 'exec', 'flfgrz': 'system'}
        lower_content = content.lower()
        for rotted, original in known_rot13.items():
            if rotted in lower_content:
                decoded_content = codecs.decode(content, 'rot_13')
                return decoded_content, {
                    "type": "rot13",
                    "original": content[:100] + "...",
                    "decoded": decoded_content[:500] + "...",
                    "confidence": 0.8
                }

        return None, {}

    def _decode_xor(self, content: str) -> Tuple[Optional[str], Dict]:
        """Detect and attempt to decode XOR encoding."""
        # Look for XOR patterns
        xor_patterns = [
            re.compile(r'-bxor\s+(\d+)', re.IGNORECASE),  # PowerShell
            re.compile(r'\^\s*(\d+)'),  # Generic XOR
            re.compile(r'xor.*?(\d+)', re.IGNORECASE),
        ]

        xor_keys = []
        for pattern in xor_patterns:
            keys = pattern.findall(content)
            xor_keys.extend(int(k) for k in keys if k.isdigit())

        if not xor_keys:
            return None, {}

        # XOR decoding would need the actual encrypted data
        # This is detection only
        return None, {
            "type": "xor_encoding_detected",
            "potential_keys": list(set(xor_keys)),
            "confidence": 0.6
        }

    def _is_printable(self, text: str, threshold: float = 0.8) -> bool:
        """Check if text is mostly printable characters."""
        if not text:
            return False
        printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return (printable_count / len(text)) >= threshold

    def detect_encoding_type(self, content: str) -> List[str]:
        """
        Detect what encoding types are present in the content.

        Returns:
            List of detected encoding types
        """
        detected = []

        # PowerShell encoded command
        if re.search(r'-e(?:nc(?:odedcommand)?)?[\s]+[A-Za-z0-9+/=]+', content, re.IGNORECASE):
            detected.append("powershell_encoded_command")

        # Base64
        if re.search(r'FromBase64String|[A-Za-z0-9+/]{40,}={0,2}', content, re.IGNORECASE):
            detected.append("base64")

        # Character codes
        if re.search(r'\[char\]\s*\d+', content, re.IGNORECASE):
            detected.append("char_array")

        # VBScript Chr
        if re.search(r'Chr\s*\(\s*\d+\s*\)', content, re.IGNORECASE):
            detected.append("vbscript_chr")

        # JavaScript unescape
        if re.search(r'unescape\s*\(', content, re.IGNORECASE):
            detected.append("javascript_unescape")

        # Compression
        if re.search(r'IO\.Compression|GzipStream|DeflateStream', content, re.IGNORECASE):
            detected.append("compression")

        # XOR
        if re.search(r'-bxor|\^.*\d+|xor', content, re.IGNORECASE):
            detected.append("xor")

        # Hex encoding
        if re.search(r'(?:0x[0-9a-fA-F]{2}[,\s]*){5,}|(?:\\x[0-9a-fA-F]{2}){5,}', content):
            detected.append("hex_encoded")

        # ROT13
        if re.search(r'rot13|str_rot13', content, re.IGNORECASE):
            detected.append("rot13")

        return detected
