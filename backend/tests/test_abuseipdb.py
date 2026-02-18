"""Tests for AbuseIPDB enrichment client."""

from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from enrichment.abuseipdb import AbuseIPDBClient


def _mock_settings(api_key="test-abuse-key"):
    s = MagicMock()
    s.abuseipdb_api_key = api_key
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


class TestCheckIP:
    @pytest.mark.asyncio
    async def test_successful_check(self):
        mock_client = _mock_http(200, {"data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 75,
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "countryCode": "CN",
            "isp": "ChinaNet",
            "domain": "chinanet.cn",
            "usageType": "Data Center/Web Hosting",
            "hostnames": [],
            "totalReports": 42,
            "numDistinctUsers": 12,
            "lastReportedAt": "2024-01-15T10:00:00Z"
        }})
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AbuseIPDBClient()
            result = await c.check_ip("1.2.3.4")
            assert result["found"] is True
            assert result["abuse_confidence_score"] == 75
            assert result["total_reports"] == 42
            assert result["source"] == "abuseipdb"

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        mock_client = _mock_http(429)
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AbuseIPDBClient()
            result = await c.check_ip("1.2.3.4")
            assert "error" in result
            assert "rate limit" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = AbuseIPDBClient()
            result = await c.check_ip("1.2.3.4")
            assert "error" in result
            assert "not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_api_error_500(self):
        mock_client = _mock_http(500, text="Server Error")
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AbuseIPDBClient()
            result = await c.check_ip("1.2.3.4")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_request_exception(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Network error")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AbuseIPDBClient()
            result = await c.check_ip("1.2.3.4")
            assert "error" in result


class TestGetBlacklist:
    @pytest.mark.asyncio
    async def test_successful_blacklist(self):
        mock_client = _mock_http(200, {"data": [
            {"ipAddress": "1.1.1.1", "abuseConfidenceScore": 100, "lastReportedAt": "2024-01-15"},
            {"ipAddress": "2.2.2.2", "abuseConfidenceScore": 95, "lastReportedAt": "2024-01-14"},
        ]})
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AbuseIPDBClient()
            result = await c.get_blacklist()
            assert result["count"] == 2
            assert len(result["ips"]) == 2
            assert result["source"] == "abuseipdb"

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = AbuseIPDBClient()
            result = await c.get_blacklist()
            assert "error" in result

    @pytest.mark.asyncio
    async def test_api_error(self):
        mock_client = _mock_http(403)
        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = AbuseIPDBClient()
            result = await c.get_blacklist()
            assert "error" in result


class TestInterpretAbuseScore:
    def _client(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            return AbuseIPDBClient()

    def test_critical_score(self):
        assert self._client().interpret_abuse_score(85)["level"] == "critical"

    def test_high_score(self):
        assert self._client().interpret_abuse_score(60)["level"] == "high"

    def test_medium_score(self):
        assert self._client().interpret_abuse_score(30)["level"] == "medium"

    def test_low_score(self):
        assert self._client().interpret_abuse_score(10)["level"] == "low"

    def test_clean_score(self):
        assert self._client().interpret_abuse_score(0)["level"] == "clean"
