"""DuckDuckGo Instant Answer search client with built-in rate limiting."""

from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass

import httpx

from hexmind.core.rate_limiter import RateLimiter


@dataclass
class SearchResult:
    """A single search result from DuckDuckGo."""

    title:   str
    url:     str
    snippet: str
    source:  str = "duckduckgo"


class DuckDuckGoSearch:
    """
    Free web search using DuckDuckGo's Instant Answer JSON API.
    Falls back to HTML scraping if API returns < 2 results.
    No API key required. Rate-limited to avoid 429s.
    """

    DDG_API_URL     = "https://api.duckduckgo.com/"
    DDG_HTML_URL    = "https://html.duckduckgo.com/html/"
    REQUEST_TIMEOUT = 10.0

    USER_AGENT = (
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    )

    def __init__(self, rate_limit: float = 2.0) -> None:
        self.rate_limit = rate_limit
        self._limiter   = RateLimiter()
        self._client    = httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT,
            headers={"User-Agent": self.USER_AGENT},
            follow_redirects=True,
        )

    async def search(
        self,
        query:       str,
        max_results: int = 5,
    ) -> list[SearchResult]:
        """
        Search DuckDuckGo and return up to max_results results.

        Strategy:
        1. Try Instant Answer JSON API — extract from RelatedTopics and AbstractText.
        2. If API returns < 2 usable results, fall back to HTML scrape.

        Rate limited. Returns [] on any network error (never raises).
        """
        await self._limiter.wait("ddg", self.rate_limit)

        results = await self._api_search(query, max_results)
        if len(results) < 2:
            results = await self._html_search(query, max_results)

        return results[:max_results]

    async def _api_search(
        self, query: str, max_results: int
    ) -> list[SearchResult]:
        """DuckDuckGo Instant Answer JSON API."""
        try:
            resp = await self._client.get(
                self.DDG_API_URL,
                params={
                    "q":             query,
                    "format":        "json",
                    "no_html":       "1",
                    "skip_disambig": "1",
                    "t":             "hexmind",
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results: list[SearchResult] = []

        # Abstract result (often the most authoritative)
        if data.get("AbstractText") and data.get("AbstractURL"):
            results.append(SearchResult(
                title   = data.get("Heading", query),
                url     = data["AbstractURL"],
                snippet = data["AbstractText"][:300],
            ))

        # Related topics (may be nested category groups)
        for topic in data.get("RelatedTopics", []):
            if len(results) >= max_results:
                break
            if "Topics" in topic:
                for sub in topic["Topics"]:
                    if len(results) >= max_results:
                        break
                    r = self._parse_topic(sub)
                    if r:
                        results.append(r)
            else:
                r = self._parse_topic(topic)
                if r:
                    results.append(r)

        return results

    def _parse_topic(self, topic: dict) -> SearchResult | None:
        """Parse a single RelatedTopics entry into a SearchResult."""
        text = topic.get("Text", "").strip()
        url  = topic.get("FirstURL", "").strip()
        if not text or not url:
            return None
        if " - " in text:
            title, _, snippet = text.partition(" - ")
        else:
            title   = _html.unescape(text[:60])
            snippet = _html.unescape(text)
        return SearchResult(
            title   = title.strip()[:100],
            url     = url,
            snippet = snippet.strip()[:300],
        )

    async def _html_search(
        self, query: str, max_results: int
    ) -> list[SearchResult]:
        """
        Fallback: scrape DuckDuckGo HTML results page.
        POST to html.duckduckgo.com with form body.
        """
        try:
            resp = await self._client.post(
                self.DDG_HTML_URL,
                data={"q": query, "b": "", "kl": ""},
                headers={
                    "User-Agent":   self.USER_AGENT,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer":      "https://html.duckduckgo.com/",
                },
            )
            resp.raise_for_status()
            html = resp.text
        except Exception:
            return []

        results: list[SearchResult] = []

        link_re = re.compile(
            r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            re.DOTALL | re.IGNORECASE,
        )
        snippet_re = re.compile(
            r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
            re.DOTALL | re.IGNORECASE,
        )

        links    = link_re.findall(html)
        snippets = [
            re.sub(r"<[^>]+>", "", s).strip()
            for s in snippet_re.findall(html)
        ]

        for i, (url, raw_title) in enumerate(links[:max_results]):
            title   = _html.unescape(re.sub(r"<[^>]+>", "", raw_title).strip())
            snippet = _html.unescape(snippets[i] if i < len(snippets) else "")
            if title and url:
                results.append(SearchResult(
                    title   = title[:100],
                    url     = url,
                    snippet = snippet[:300],
                ))

        return results

    async def search_cve_context(self, cve_id: str) -> list[SearchResult]:
        """Search for exploit/PoC context around a specific CVE."""
        return await self.search(
            f"{cve_id} exploit vulnerability proof of concept",
            max_results=3,
        )

    async def search_service_vulns(
        self, service: str, version: str
    ) -> list[SearchResult]:
        """Search for known vulnerabilities in a service version."""
        return await self.search(
            f"{service} {version} CVE vulnerability 2023 2024",
            max_results=5,
        )

    def format_for_prompt(self, results: list[SearchResult]) -> str:
        """Format search results as a readable text block for AI context."""
        if not results:
            return "  No results found.\n"
        lines: list[str] = []
        for i, r in enumerate(results, 1):
            lines.append(f"  [{i}] {r.title}")
            lines.append(f"      {r.url}")
            if r.snippet:
                lines.append(f"      {r.snippet[:200]}")
        return "\n".join(lines)

    async def close(self) -> None:
        await self._client.aclose()
