"""Security middleware for the malware analysis platform.

Provides rate limiting, API key authentication, and structured request logging.
"""

import time
import logging
import secrets
import collections
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config import get_settings

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token bucket rate limiter with per-client tracking.

    Tracks request rates per client IP using a token bucket algorithm.
    Each client gets a bucket that refills at a steady rate and allows
    short bursts up to the configured burst size.
    """

    # Endpoints exempt from rate limiting (health checks, root)
    EXEMPT_PATHS = {"/health", "/"}

    def __init__(self, app, requests_per_minute: int = 60, burst: int = 10):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self.refill_rate = requests_per_minute / 60.0  # tokens per second
        # Per-client buckets: {client_ip: {"tokens": float, "last_refill": float}}
        self.buckets: dict[str, dict[str, float]] = {}

    def _get_client_ip(self, request) -> str:
        """Extract client IP, respecting X-Forwarded-For behind a reverse proxy."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Take the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _consume_token(self, client_ip: str) -> tuple[bool, float]:
        """Try to consume a token from the client's bucket.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.monotonic()

        if client_ip not in self.buckets:
            # Initialize bucket with full burst capacity minus the current request
            self.buckets[client_ip] = {
                "tokens": self.burst - 1,
                "last_refill": now,
            }
            return True, 0.0

        bucket = self.buckets[client_ip]

        # Refill tokens based on elapsed time
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(
            self.burst,
            bucket["tokens"] + elapsed * self.refill_rate,
        )
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True, 0.0
        else:
            # Calculate how long until one token is available
            deficit = 1.0 - bucket["tokens"]
            retry_after = deficit / self.refill_rate
            return False, retry_after

    async def dispatch(self, request, call_next):
        # Skip rate limiting for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        allowed, retry_after = self._consume_token(client_ip)

        if not allowed:
            retry_after_int = int(retry_after) + 1  # Round up to next whole second
            logger.warning(
                "Rate limit exceeded for client_ip=%s path=%s retry_after=%ds",
                client_ip,
                request.url.path,
                retry_after_int,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please slow down.",
                    "retry_after_seconds": retry_after_int,
                },
                headers={"Retry-After": str(retry_after_int)},
            )

        return await call_next(request)


class AuthMiddleware(BaseHTTPMiddleware):
    """API key authentication middleware.

    Validates X-API-Key header on all /api/ routes using timing-safe
    comparison to prevent timing attacks. Certain public and webhook
    endpoints are exempt.
    """

    # Paths that do not require API key authentication
    EXEMPT_PATHS = {"/", "/health", "/docs", "/openapi.json"}

    # Path prefixes that are exempt (webhooks use their own auth mechanism)
    EXEMPT_PREFIXES = ("/api/webhooks/",)

    async def dispatch(self, request, call_next):
        path = request.url.path

        # Check exact path exemptions
        if path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Check prefix exemptions
        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        # Only enforce auth on /api/ routes
        if not path.startswith("/api/"):
            return await call_next(request)

        # Validate API key
        settings = get_settings()
        api_key = request.headers.get("x-api-key")

        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key. Provide it via the X-API-Key header."},
            )

        # Timing-safe comparison to prevent timing-based side-channel attacks
        if not secrets.compare_digest(api_key, settings.api_key):
            logger.warning(
                "Invalid API key attempt from client_ip=%s path=%s",
                request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown"),
                path,
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API key."},
            )

        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Structured request logging middleware.

    Logs each request with method, path, status code, duration, and client IP
    in a structured format suitable for log aggregation.
    """

    # Paths to skip logging (too noisy for continuous health checks)
    SKIP_PATHS = {"/health"}

    def _get_client_ip(self, request) -> str:
        """Extract client IP, respecting X-Forwarded-For."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request, call_next):
        path = request.url.path

        # Skip logging for noisy endpoints
        if path in self.SKIP_PATHS:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        start_time = time.monotonic()

        try:
            response = await call_next(request)
        except Exception:
            # Log the failed request before re-raising
            duration_ms = (time.monotonic() - start_time) * 1000
            logger.error(
                'request_log: {"method": "%s", "path": "%s", "status_code": 500, '
                '"duration_ms": %.1f, "client_ip": "%s", "error": true}',
                request.method,
                path,
                duration_ms,
                client_ip,
            )
            raise

        duration_ms = (time.monotonic() - start_time) * 1000
        log_level = logging.WARNING if response.status_code >= 400 else logging.INFO

        logger.log(
            log_level,
            'request_log: {"method": "%s", "path": "%s", "status_code": %d, '
            '"duration_ms": %.1f, "client_ip": "%s"}',
            request.method,
            path,
            response.status_code,
            duration_ms,
            client_ip,
        )

        return response
