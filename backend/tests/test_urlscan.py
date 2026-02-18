"""Tests for urlscan.io enrichment client."""

from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from enrichment.urlscan import URLScanClient


def _mock_settings(api_key="test-urlscan-key"):
    s = MagicMock()
    s.urlscan_api_key = api_key
    return s


def _mock_response(status_code, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    return resp


class TestScanURL:
    @pytest.mark.asyncio
    async def test_successful_scan(self):
        submit_resp = _mock_response(200, {"uuid": "abc-123"})
        result_resp = _mock_response(200, {
            "page": {"url": "https://example.com", "domain": "example.com", "ip": "93.184.216.34",
                     "country": "US", "server": "nginx", "status": 200, "title": "Example"},
            "lists": {"urls": [], "ips": [], "domains": [], "certificates": []},
            "stats": {"uniqIPs": 1, "uniqCountries": 1, "totalLinks": 5},
            "verdicts": {"overall": {"malicious": False, "score": 0, "categories": [], "tags": [], "brands": []}}
        })

        mock_client = AsyncMock()
        mock_client.post.return_value = submit_resp
        mock_client.get.return_value = result_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            c = URLScanClient()
            result = await c.scan_url("https://example.com")
            assert result["domain"] == "example.com"
            assert result["malicious"] is False
            assert result["source"] == "urlscan"

    @pytest.mark.asyncio
    async def test_api_key_not_configured(self):
        with patch("config.get_settings", return_value=_mock_settings(api_key=None)):
            c = URLScanClient()
            result = await c.scan_url("https://example.com")
            assert "error" in result
            assert "not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_rate_limit(self):
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(429)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = URLScanClient()
            result = await c.scan_url("https://example.com")
            assert "error" in result
            assert "rate limit" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_api_error(self):
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(500, text="Error")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = URLScanClient()
            result = await c.scan_url("https://example.com")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_request_exception(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("Timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = URLScanClient()
            result = await c.scan_url("https://example.com")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_scan_pending_timeout(self):
        submit_resp = _mock_response(200, {"uuid": "abc-123"})

        mock_client = AsyncMock()
        mock_client.post.return_value = submit_resp
        mock_client.get.return_value = _mock_response(404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            c = URLScanClient()
            result = await c.scan_url("https://example.com")
            assert result["status"] == "pending"


class TestSearch:
    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(200, {
            "total": 1,
            "results": [{
                "page": {"domain": "example.com", "ip": "93.184.216.34", "country": "US",
                         "server": "nginx", "title": "Example", "status": 200},
                "task": {"uuid": "abc-123", "url": "https://example.com", "time": "2024-01-15"}
            }]
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = URLScanClient()
            result = await c.search("domain:example.com")
            assert result["total"] == 1
            assert len(result["results"]) == 1
            assert result["source"] == "urlscan"

    @pytest.mark.asyncio
    async def test_api_error(self):
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(500)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = URLScanClient()
            result = await c.search("domain:example.com")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_request_exception(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("config.get_settings", return_value=_mock_settings()), \
             patch("httpx.AsyncClient", return_value=mock_client):
            c = URLScanClient()
            result = await c.search("domain:example.com")
            assert "error" in result


class TestLookupDomain:
    @pytest.mark.asyncio
    async def test_delegates_to_search(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = URLScanClient()
            with patch.object(c, "search", new_callable=AsyncMock, return_value={"results": []}) as mock_search:
                await c.lookup_domain("example.com")
                mock_search.assert_called_once_with("domain:example.com", size=10)


class TestLookupIP:
    @pytest.mark.asyncio
    async def test_delegates_to_search(self):
        with patch("config.get_settings", return_value=_mock_settings()):
            c = URLScanClient()
            with patch.object(c, "search", new_callable=AsyncMock, return_value={"results": []}) as mock_search:
                await c.lookup_ip("8.8.8.8")
                mock_search.assert_called_once_with("ip:8.8.8.8", size=10)
