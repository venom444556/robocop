"""Tests for security middleware (rate limiting, auth, request logging)."""

import sys
import os
import time
from unittest.mock import patch, MagicMock

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from middleware import RateLimitMiddleware, AuthMiddleware, RequestLoggingMiddleware


# ===================================================================
# RateLimitMiddleware  --  Token Bucket
# ===================================================================

class TestRateLimitTokenBucket:
    """Unit tests for the token-bucket rate limiter."""

    def _make_middleware(self, rpm=60, burst=5):
        """Create a RateLimitMiddleware with a dummy app."""
        dummy_app = MagicMock()
        return RateLimitMiddleware(dummy_app, requests_per_minute=rpm, burst=burst)

    def test_first_request_allowed(self):
        mw = self._make_middleware(rpm=60, burst=5)
        allowed, _ = mw._consume_token("1.2.3.4")
        assert allowed is True

    def test_burst_requests_allowed(self):
        """Up to `burst` requests should be allowed immediately."""
        mw = self._make_middleware(rpm=60, burst=5)
        for i in range(5):
            allowed, _ = mw._consume_token("1.2.3.4")
            assert allowed is True, f"Request {i+1} should be allowed within burst"

    def test_exceeding_burst_rejected(self):
        """The (burst + 1)th request without token refill should be rejected."""
        mw = self._make_middleware(rpm=60, burst=3)
        for _ in range(3):
            mw._consume_token("1.2.3.4")
        # 4th request should be denied
        allowed, retry_after = mw._consume_token("1.2.3.4")
        assert allowed is False
        assert retry_after > 0

    def test_different_clients_independent(self):
        """Each client IP gets its own bucket."""
        mw = self._make_middleware(rpm=60, burst=2)
        # Exhaust client A
        mw._consume_token("client-a")
        mw._consume_token("client-a")
        allowed_a, _ = mw._consume_token("client-a")
        assert allowed_a is False

        # Client B should still have tokens
        allowed_b, _ = mw._consume_token("client-b")
        assert allowed_b is True

    def test_tokens_refill_over_time(self):
        """After waiting, tokens should be replenished."""
        mw = self._make_middleware(rpm=600, burst=2)  # 10 tokens/sec
        # Exhaust tokens
        mw._consume_token("1.2.3.4")
        mw._consume_token("1.2.3.4")
        allowed, _ = mw._consume_token("1.2.3.4")
        assert allowed is False

        # Simulate time passing by manipulating last_refill
        mw.buckets["1.2.3.4"]["last_refill"] -= 1.0  # pretend 1 second passed
        allowed, _ = mw._consume_token("1.2.3.4")
        assert allowed is True

    def test_tokens_capped_at_burst(self):
        """Tokens should never exceed the burst limit even after long idle."""
        mw = self._make_middleware(rpm=60, burst=5)
        mw._consume_token("1.2.3.4")
        # Simulate very long idle
        mw.buckets["1.2.3.4"]["last_refill"] -= 3600  # 1 hour
        # Consume and check we get burst-many tokens at most
        for i in range(5):
            allowed, _ = mw._consume_token("1.2.3.4")
            assert allowed is True
        # The 6th should fail (no more than burst)
        allowed, _ = mw._consume_token("1.2.3.4")
        assert allowed is False

    def test_retry_after_is_positive(self):
        mw = self._make_middleware(rpm=60, burst=1)
        mw._consume_token("1.2.3.4")
        allowed, retry_after = mw._consume_token("1.2.3.4")
        assert allowed is False
        assert retry_after > 0

    def test_exempt_paths(self):
        """EXEMPT_PATHS should bypass rate limiting."""
        assert "/health" in RateLimitMiddleware.EXEMPT_PATHS
        assert "/" in RateLimitMiddleware.EXEMPT_PATHS

    def test_get_client_ip_from_x_forwarded_for(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {"x-forwarded-for": "4.3.2.1, 10.0.0.1"}
        ip = mw._get_client_ip(request)
        assert ip == "4.3.2.1"

    def test_get_client_ip_direct(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {}
        request.client.host = "5.6.7.8"
        ip = mw._get_client_ip(request)
        assert ip == "5.6.7.8"


# ===================================================================
# RateLimitMiddleware  --  dispatch (integration via test client)
# ===================================================================

class TestRateLimitDispatch:
    """Integration-level tests for rate limiting via the HTTP client."""

    @pytest.mark.asyncio
    async def test_health_endpoint_not_rate_limited(self, client):
        """The /health endpoint is exempt from rate limiting."""
        for _ in range(50):
            resp = await client.get("/health")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_root_endpoint_not_rate_limited(self, client):
        """The / endpoint is exempt from rate limiting."""
        for _ in range(50):
            resp = await client.get("/")
            assert resp.status_code == 200


# ===================================================================
# AuthMiddleware
# ===================================================================

class TestAuthMiddleware:
    """Tests for API key authentication middleware."""

    def test_exempt_paths_defined(self):
        """Check that the expected public paths are exempt."""
        assert "/" in AuthMiddleware.EXEMPT_PATHS
        assert "/health" in AuthMiddleware.EXEMPT_PATHS
        assert "/docs" in AuthMiddleware.EXEMPT_PATHS
        assert "/openapi.json" in AuthMiddleware.EXEMPT_PATHS

    def test_webhook_prefix_exempt(self):
        """Webhook paths should be exempt."""
        assert "/api/webhooks/" in AuthMiddleware.EXEMPT_PREFIXES

    @pytest.mark.asyncio
    async def test_missing_api_key_rejected(self):
        """Requests to /api/ routes without X-API-Key should get 401."""
        import httpx
        from main import app as real_app
        from middleware import AuthMiddleware

        # Add AuthMiddleware to a fresh copy of the app for this test
        # We test by directly calling dispatch on the middleware
        dummy_app = MagicMock()
        mw = AuthMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/submissions/"
        request.headers = {}  # No API key

        call_next = MagicMock()
        response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_api_key_accepted(self):
        """Requests with the correct X-API-Key should be forwarded."""
        from config import get_settings

        settings = get_settings()
        dummy_app = MagicMock()
        mw = AuthMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/submissions/"
        request.headers = {"x-api-key": settings.api_key}
        request.client.host = "127.0.0.1"

        # call_next is async
        async def mock_call_next(req):
            resp = MagicMock()
            resp.status_code = 200
            return resp

        response = await mw.dispatch(request, mock_call_next)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self):
        """Requests with a wrong API key should get 401."""
        dummy_app = MagicMock()
        mw = AuthMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/submissions/"
        request.headers = {"x-api-key": "totally-wrong-key-12345"}
        request.client.host = "127.0.0.1"

        call_next = MagicMock()
        response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_exempt_path_bypasses_auth(self):
        """Requests to exempt paths should not need an API key."""
        dummy_app = MagicMock()
        mw = AuthMiddleware(dummy_app)

        for path in ["/", "/health", "/docs", "/openapi.json"]:
            request = MagicMock()
            request.url.path = path
            request.headers = {}  # No API key

            async def mock_call_next(req):
                resp = MagicMock()
                resp.status_code = 200
                return resp

            response = await mw.dispatch(request, mock_call_next)
            assert response.status_code == 200, f"Path {path} should be exempt"

    @pytest.mark.asyncio
    async def test_webhook_prefix_bypasses_auth(self):
        """Webhook paths should bypass auth."""
        dummy_app = MagicMock()
        mw = AuthMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/webhooks/analysis-trigger"
        request.headers = {}  # No API key

        async def mock_call_next(req):
            resp = MagicMock()
            resp.status_code = 200
            return resp

        response = await mw.dispatch(request, mock_call_next)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_non_api_path_bypasses_auth(self):
        """Non /api/ paths should not require auth."""
        dummy_app = MagicMock()
        mw = AuthMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/some/other/path"
        request.headers = {}  # No API key

        async def mock_call_next(req):
            resp = MagicMock()
            resp.status_code = 200
            return resp

        response = await mw.dispatch(request, mock_call_next)
        assert response.status_code == 200


# ===================================================================
# RequestLoggingMiddleware
# ===================================================================

class TestRequestLoggingMiddleware:
    """Tests for the structured request logging middleware."""

    def test_skip_paths_defined(self):
        """The /health path should be in the skip list."""
        assert "/health" in RequestLoggingMiddleware.SKIP_PATHS

    def test_get_client_ip_from_forwarded(self):
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)
        request = MagicMock()
        request.headers = {"x-forwarded-for": "9.8.7.6, 10.0.0.1"}
        assert mw._get_client_ip(request) == "9.8.7.6"

    def test_get_client_ip_fallback(self):
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)
        request = MagicMock()
        request.headers = {}
        request.client.host = "11.22.33.44"
        assert mw._get_client_ip(request) == "11.22.33.44"

    @pytest.mark.asyncio
    async def test_logging_skip_health(self):
        """Requests to /health should not be logged."""
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/health"

        expected_resp = MagicMock()
        expected_resp.status_code = 200

        async def mock_call_next(req):
            return expected_resp

        with patch("middleware.logger") as mock_logger:
            response = await mw.dispatch(request, mock_call_next)
            assert response.status_code == 200
            # Logger should not have been called for /health
            mock_logger.log.assert_not_called()
            mock_logger.info.assert_not_called()

    @pytest.mark.asyncio
    async def test_logging_non_skipped_path(self):
        """Requests to non-skipped paths should be logged."""
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/submissions/"
        request.method = "GET"
        request.headers = {}
        request.client.host = "1.2.3.4"

        expected_resp = MagicMock()
        expected_resp.status_code = 200

        async def mock_call_next(req):
            return expected_resp

        with patch("middleware.logger") as mock_logger:
            response = await mw.dispatch(request, mock_call_next)
            assert response.status_code == 200
            # Logger.log should have been called
            mock_logger.log.assert_called_once()
            args = mock_logger.log.call_args
            # The log message should contain the path
            log_message = args[0][1] if len(args[0]) > 1 else ""
            assert "submissions" in str(args)

    @pytest.mark.asyncio
    async def test_logging_error_status_uses_warning(self):
        """Responses with status >= 400 should be logged at WARNING level."""
        import logging
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/not-found"
        request.method = "GET"
        request.headers = {}
        request.client.host = "1.2.3.4"

        expected_resp = MagicMock()
        expected_resp.status_code = 404

        async def mock_call_next(req):
            return expected_resp

        with patch("middleware.logger") as mock_logger:
            await mw.dispatch(request, mock_call_next)
            # Should log at WARNING level for 4xx
            mock_logger.log.assert_called_once()
            log_level = mock_logger.log.call_args[0][0]
            assert log_level == logging.WARNING

    @pytest.mark.asyncio
    async def test_logging_success_uses_info(self):
        """Responses with status < 400 should be logged at INFO level."""
        import logging
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/data"
        request.method = "GET"
        request.headers = {}
        request.client.host = "1.2.3.4"

        expected_resp = MagicMock()
        expected_resp.status_code = 200

        async def mock_call_next(req):
            return expected_resp

        with patch("middleware.logger") as mock_logger:
            await mw.dispatch(request, mock_call_next)
            mock_logger.log.assert_called_once()
            log_level = mock_logger.log.call_args[0][0]
            assert log_level == logging.INFO

    @pytest.mark.asyncio
    async def test_logging_on_exception(self):
        """If call_next raises, the error should be logged and re-raised."""
        dummy_app = MagicMock()
        mw = RequestLoggingMiddleware(dummy_app)

        request = MagicMock()
        request.url.path = "/api/boom"
        request.method = "GET"
        request.headers = {}
        request.client.host = "1.2.3.4"

        async def mock_call_next(req):
            raise RuntimeError("boom")

        with patch("middleware.logger") as mock_logger:
            with pytest.raises(RuntimeError, match="boom"):
                await mw.dispatch(request, mock_call_next)
            # Error should have been logged
            mock_logger.error.assert_called_once()
