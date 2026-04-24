"""Web search and CVE lookup modules."""

from hexmind.search.duckduckgo import DuckDuckGoSearch, SearchResult
from hexmind.search.cve_lookup import CVELookup, CVEDetail

__all__ = [
    "DuckDuckGoSearch",
    "SearchResult",
    "CVELookup",
    "CVEDetail",
]
