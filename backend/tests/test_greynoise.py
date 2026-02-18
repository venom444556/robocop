"""Tests for GreyNoise enrichment client."""

from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from enrichment.greynoise import GreyNoiseClient


def _mock_settings(api_key="test-gn-key"):
    s = MagicMock()
    s.greynoise_api_key = api_key
    return s


def _mock_http(status_code, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    client = AsyncMock()
    client.get.return_value = resp
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


class TestLookupIP:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_client = _mock_http(200, {
            "ip": "8.8.8.8",
            "noise": True,
            "riot": False,
            "classification": "benign",
            "name": "Google DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "last_seen": "2024-01-15",
            "message": "IP has been observed"
        })
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = GreyNoiseClient()
            result = await c.lookup_ip("8.8.8.8")
            assert result["found"] is True
            assert result["noise"] is True
            assert result["classification"] == "benign"
            assert result["source"] == "greynoise"

    @pytest.mark.asyncio
    async def test_ip_not_found(self):
        mock_client = _mock_http(404)
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = GreyNoiseClient()
            result = await c.lookup_ip("192.168.1.1")
            assert result["found"] is False
            assert result["classification"] == "unknown"
            assert result["source"] == "greynoise"

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = GreyNoiseClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result
            assert "not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_api_error_500(self):
        mock_client = _mock_http(500, text="Internal Server Error")
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = GreyNoiseClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result
            assert "500" in result["error"]

    @pytest.mark.asyncio
    async def test_request_exception(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Connection timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = GreyNoiseClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result
            assert "Connection timeout" in result["error"]


class TestInterpretClassification:
    def test_benign(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = GreyNoiseClient()
            result = c.interpret_classification("benign")
            assert result["level"] == "safe"
            assert result["action"] == "allow"

    def test_malicious(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = GreyNoiseClient()
            result = c.interpret_classification("malicious")
            assert result["level"] == "critical"
            assert result["action"] == "block"

    def test_unknown(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = GreyNoiseClient()
            result = c.interpret_classification("unknown")
            assert result["level"] == "low"
            assert result["action"] == "investigate"

    def test_unrecognized(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = GreyNoiseClient()
            result = c.interpret_classification("bogus")
            assert result["level"] == "unknown"
            assert result["action"] == "investigate"
