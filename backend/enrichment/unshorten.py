"""URL expansion service for shortened URLs."""

from typing import Dict, Optional


class UnshortenClient:
    """Client for URL unshortening services."""

    # Known URL shortener domains
    SHORTENER_DOMAINS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im',
        'cli.gs', 'short.to', 'budurl.com', 'ping.fm',
        'post.ly', 'just.as', 'bkite.com', 'snipr.com',
        'fic.kr', 'loopt.us', 'doiop.com', 'short.ie',
        'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'rb.gy',
        'cutt.ly', 'shorturl.at', 'tiny.cc', 'shorte.st',
        'v.gd', 'qr.ae', 'bc.vc', 'u.to'
    }

    def __init__(self):
        """Initialize the unshorten client."""
        pass

    def is_shortened_url(self, url: str) -> bool:
        """
        Check if a URL is from a known URL shortener.

        Args:
            url: URL to check

        Returns:
            True if URL is shortened
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]

        return domain in self.SHORTENER_DOMAINS

    async def expand(self, url: str) -> Dict:
        """
        Expand a shortened URL to its full destination.

        Args:
            url: Shortened URL to expand

        Returns:
            Dictionary with expansion results
        """
        import httpx

        result = {
            "original_url": url,
            "expanded_url": None,
            "redirect_chain": [],
            "is_shortened": self.is_shortened_url(url),
            "error": None
        }

        # Try unshorten.me API first
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # URL-encode the URL for the API
                from urllib.parse import quote
                encoded_url = quote(url, safe='')

                response = await client.get(
                    f"https://unshorten.me/json/{encoded_url}",
                    follow_redirects=False
                )

                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        result["expanded_url"] = data.get("resolved_url")
                        result["usage_count"] = data.get("usage_count")
                        return result

        except Exception as e:
            # Fall back to manual expansion
            pass

        # Manual expansion by following redirects
        try:
            await self._follow_redirects(url, result)
        except Exception as e:
            result["error"] = str(e)

        return result

    async def _follow_redirects(self, url: str, result: Dict, max_redirects: int = 10):
        """
        Follow redirects manually to expand URL.

        Args:
            url: URL to expand
            result: Result dictionary to populate
            max_redirects: Maximum number of redirects to follow
        """
        import httpx

        current_url = url
        redirect_count = 0

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            while redirect_count < max_redirects:
                try:
                    response = await client.head(current_url, follow_redirects=False)

                    result["redirect_chain"].append({
                        "url": current_url,
                        "status_code": response.status_code
                    })

                    # Check for redirect
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if location:
                            # Handle relative URLs
                            if not location.startswith(('http://', 'https://')):
                                from urllib.parse import urljoin
                                location = urljoin(current_url, location)

                            current_url = location
                            redirect_count += 1
                        else:
                            break
                    else:
                        # No more redirects
                        break

                except (httpx.RequestError, httpx.ConnectError) as e:
                    # Log SSL/connection failures, then try GET as fallback
                    import logging
                    logging.getLogger(__name__).warning("HEAD request failed for %s: %s", current_url, e)
                    try:
                        response = await client.get(current_url, follow_redirects=False)
                        result["redirect_chain"].append({
                            "url": current_url,
                            "status_code": response.status_code
                        })

                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("location")
                            if location:
                                if not location.startswith(('http://', 'https://')):
                                    from urllib.parse import urljoin
                                    location = urljoin(current_url, location)
                                current_url = location
                                redirect_count += 1
                            else:
                                break
                        else:
                            break
                    except Exception as inner_e:
                        logging.getLogger(__name__).warning(
                            "GET fallback also failed for %s: %s", current_url, inner_e
                        )
                        break

        result["expanded_url"] = current_url
        result["redirect_count"] = redirect_count

    async def expand_batch(self, urls: list) -> Dict:
        """
        Expand multiple shortened URLs.

        Args:
            urls: List of URLs to expand

        Returns:
            Dictionary with expansion results for each URL
        """
        import asyncio

        results = {}
        tasks = []

        for url in urls:
            if self.is_shortened_url(url):
                tasks.append((url, self.expand(url)))

        if not tasks:
            return {"message": "No shortened URLs found", "results": {}}

        expanded = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

        for (url, _), expansion in zip(tasks, expanded):
            if isinstance(expansion, Exception):
                results[url] = {"error": str(expansion)}
            else:
                results[url] = expansion

        return {
            "total_checked": len(urls),
            "shortened_found": len(tasks),
            "results": results
        }
