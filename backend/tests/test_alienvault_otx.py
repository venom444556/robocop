"""Tests for AlienVault OTX enrichment client."""

from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from enrichment.alienvault_otx import AlienVaultOTXClient


def _mock_settings(api_key="test-otx-key"):
    s = MagicMock()
    s.alienvault_otx_api_key = api_key
    return s


def _mock_response(status_code, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    return resp


def _general_ip_data():
    return {
        "country_name": "United States",
        "country_code": "US",
        "asn": "AS15169",
        "whois": "Google LLC",
        "pulse_info": {
            "count": 2,
            "pulses": [
                {"id": "p1", "name": "DNS Abuse", "description": "Test pulse",
                 "created": "2024-01-01", "tags": ["dns"], "adversary": "APT29",
                 "targeted_countries": ["US"], "malware_families": ["Cobalt Strike"],
                 "attack_ids": [{"id": "T1071"}]}
            ]
        }
    }


class TestLookupIP:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        general_resp = _mock_response(200, _general_ip_data())
        reputation_resp = _mock_response(200, {"reputation": {"threat_score": 3}})

        mock_client = AsyncMock()
        mock_client.get.side_effect = [general_resp, reputation_resp]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_ip("8.8.8.8")
            assert result["found"] is True
            assert result["pulse_count"] == 2
            assert result["source"] == "alienvault_otx"
            assert result["country"] == "United States"

    @pytest.mark.asyncio
    async def test_not_found(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_ip("10.0.0.1")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = AlienVaultOTXClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result
            assert "not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_api_error(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(500, text="Error")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_request_exception(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result


class TestLookupDomain:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(200, {
            "whois": "Registrar: Example Registrar",
            "pulse_info": {"count": 1, "pulses": [
                {"id": "p1", "name": "Phishing", "description": "Test",
                 "created": "2024-01-01", "tags": ["phish"], "adversary": None,
                 "malware_families": [], "attack_ids": []}
            ]},
            "alexa": "example.com"
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_domain("example.com")
            assert result["found"] is True
            assert result["pulse_count"] == 1
            assert result["source"] == "alienvault_otx"

    @pytest.mark.asyncio
    async def test_not_found(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_domain("nonexistent.example")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = AlienVaultOTXClient()
            result = await c.lookup_domain("example.com")
            assert "error" in result


class TestLookupHash:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        general_resp = _mock_response(200, {
            "pulse_info": {"count": 3, "pulses": [
                {"id": "p1", "name": "Malware Campaign", "description": "Bad stuff",
                 "tags": ["malware"], "adversary": "APT28",
                 "malware_families": ["AgentTesla"], "attack_ids": []}
            ]}
        })
        analysis_resp = _mock_response(200, {"analysis": {}})

        mock_client = AsyncMock()
        mock_client.get.side_effect = [general_resp, analysis_resp]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        sha256 = "a" * 64
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_hash(sha256)
            assert result["found"] is True
            assert result["pulse_count"] == 3
            assert result["source"] == "alienvault_otx"

    @pytest.mark.asyncio
    async def test_invalid_hash_length(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = AlienVaultOTXClient()
            result = await c.lookup_hash("tooshort")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = AlienVaultOTXClient()
            result = await c.lookup_hash("a" * 64)
            assert "error" in result


class TestLookupURL:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(200, {
            "pulse_info": {"count": 1, "pulses": [
                {"id": "p1", "name": "URL Threat", "description": "Phishing URL",
                 "tags": ["phishing"], "adversary": None, "malware_families": []}
            ]}
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_url("https://evil.example.com/payload")
            assert result["found"] is True
            assert result["source"] == "alienvault_otx"

    @pytest.mark.asyncio
    async def test_api_error(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(500)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AlienVaultOTXClient()
            result = await c.lookup_url("https://example.com")
            assert "error" in result
