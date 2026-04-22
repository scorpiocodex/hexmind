"""CVE lookup client querying CIRCL and NVD APIs for vulnerability details."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


@dataclass
class CVEDetail:
    """Structured representation of a single CVE entry."""

    cve_id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    published_date: str
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    affected_products: list[str] = field(default_factory=list)
    source: str = "circl"


class CVELookup:
    """Fetches CVE details from cve.circl.lu (primary) and NVD (secondary)."""

    CIRCL_BASE: str = "https://cve.circl.lu/api"
    NVD_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT: float = 6.0

    def __init__(self) -> None:
        """Initialize the CVE lookup client."""
        self._last_nvd_request: float = 0.0

    async def lookup(self, cve_id: str) -> CVEDetail | None:
        """Fetch details for a single CVE ID; returns None if not found."""
        raise NotImplementedError("TODO: implement")

    async def lookup_batch(
        self, cve_ids: list[str]
    ) -> dict[str, CVEDetail]:
        """Fetch details for multiple CVE IDs and return a cve_id → CVEDetail map."""
        raise NotImplementedError("TODO: implement")

    async def search_product(
        self, vendor: str, product: str
    ) -> list[CVEDetail]:
        """Search CIRCL for CVEs affecting a specific vendor/product combination."""
        raise NotImplementedError("TODO: implement")

    def format_for_prompt(self, cve: CVEDetail) -> str:
        """Format a CVEDetail into a compact prompt-ready string."""
        raise NotImplementedError("TODO: implement")

    @staticmethod
    def extract_cve_ids(text: str) -> list[str]:
        """Return all unique CVE IDs found in the given text string."""
        raise NotImplementedError("TODO: implement")
