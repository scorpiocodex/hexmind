"""CVE lookup client querying CIRCL and NVD APIs for vulnerability details."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from hexmind.core.rate_limiter import RateLimiter


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class CVEDetail:
    """Structured representation of a single CVE entry."""

    cve_id:            str
    description:       str
    cvss_score:        Optional[float]
    cvss_vector:       Optional[str]
    severity:          str                # critical|high|medium|low|none
    published_date:    str
    references:        list[str]          = field(default_factory=list)
    exploit_available: bool               = False
    affected_products: list[str]          = field(default_factory=list)
    source:            str                = "circl.lu"


class CVELookup:
    """
    CVE data aggregator using free, no-key APIs:
      1. cve.circl.lu   — primary (generous rate limits)
      2. NVD REST API   — fallback (5 req / 30s without key)

    Results are cached in-process to avoid repeat network calls.
    """

    CIRCL_BASE = "https://cve.circl.lu/api"
    NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE   = 6.0   # seconds between NVD requests (no-key limit)
    CIRCL_RATE = 1.0

    def __init__(self) -> None:
        self._cache:   dict[str, CVEDetail] = {}
        self._limiter  = RateLimiter()
        self._client   = httpx.AsyncClient(
            timeout=15.0,
            headers={"User-Agent": "HexMind/0.1 CVE-Lookup"},
            follow_redirects=True,
        )

    # ── Public API ──────────────────────────────────────────────────────────

    async def lookup(self, cve_id: str) -> Optional[CVEDetail]:
        """
        Look up a single CVE ID. Returns CVEDetail or None.

        Flow:
          1. Normalize to uppercase
          2. Check in-process cache
          3. Try CIRCL API
          4. On failure, try NVD API (rate-limited separately)
          5. Cache and return result
        """
        cve_id = cve_id.strip().upper()
        if not _CVE_PATTERN.match(cve_id):
            return None

        if cve_id in self._cache:
            return self._cache[cve_id]

        result = await self._lookup_circl(cve_id)
        if not result:
            result = await self._lookup_nvd(cve_id)

        if result:
            self._cache[cve_id] = result
        return result

    async def lookup_batch(
        self, cve_ids: list[str]
    ) -> dict[str, CVEDetail]:
        """
        Look up multiple CVE IDs with rate limiting between each.
        Returns dict of cve_id → CVEDetail for found entries only.
        """
        results: dict[str, CVEDetail] = {}
        for i, cve_id in enumerate(cve_ids):
            detail = await self.lookup(cve_id)
            if detail:
                results[cve_id.upper()] = detail
            if i < len(cve_ids) - 1:
                await self._limiter.wait("circl_batch", self.CIRCL_RATE)
        return results

    async def search_product(
        self, vendor: str, product: str
    ) -> list[CVEDetail]:
        """
        Search for CVEs affecting vendor/product via CIRCL API.
        GET /api/search/{vendor}/{product}
        Returns top 10 by CVSS score descending.
        """
        await self._limiter.wait("circl", self.CIRCL_RATE)
        try:
            resp = await self._client.get(
                f"{self.CIRCL_BASE}/search/{vendor}/{product}",
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        entries = data if isinstance(data, list) else data.get("data", [])
        results: list[CVEDetail] = []
        for entry in entries[:20]:
            detail = self._parse_circl(entry)
            if detail:
                results.append(detail)

        results.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)
        return results[:10]

    def format_for_prompt(self, cve: CVEDetail) -> str:
        """Format a CVEDetail as a compact text block for AI context."""
        lines = [
            f"  ID:          {cve.cve_id}",
            f"  Severity:    {cve.severity.upper()} "
            f"(CVSS: {cve.cvss_score or 'N/A'})",
            f"  Published:   {cve.published_date}",
            f"  Exploit:     "
            f"{'YES — public exploit available' if cve.exploit_available else 'Not confirmed'}",
        ]
        if cve.description:
            lines.append(f"  Description: {cve.description[:400]}")
        if cve.affected_products:
            lines.append(
                f"  Affects:     {', '.join(cve.affected_products[:5])}"
            )
        if cve.references:
            lines.append(f"  References:  {cve.references[0]}")
        return "\n".join(lines)

    @staticmethod
    def extract_cve_ids(text: str) -> list[str]:
        """Extract all unique CVE IDs found in arbitrary text."""
        found = _CVE_PATTERN.findall(text)
        return list(dict.fromkeys(c.upper() for c in found))

    async def close(self) -> None:
        await self._client.aclose()

    # ── Private: CIRCL API ──────────────────────────────────────────────────

    async def _lookup_circl(self, cve_id: str) -> Optional[CVEDetail]:
        """GET https://cve.circl.lu/api/cve/{CVE_ID}"""
        await self._limiter.wait("circl", self.CIRCL_RATE)
        try:
            resp = await self._client.get(
                f"{self.CIRCL_BASE}/cve/{cve_id}",
                timeout=10.0,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        if not data:
            return None

        return self._parse_circl(data)

    def _parse_circl(self, data: dict) -> Optional[CVEDetail]:
        """
        Parse CIRCL API response into CVEDetail.
        Schema: id, summary, cvss, cvss-vector, Published, references,
                vulnerable_configuration (CPE list)
        """
        cve_id = data.get("id", "").upper()
        if not cve_id:
            return None

        cvss = data.get("cvss")
        try:
            cvss_score: Optional[float] = float(cvss) if cvss else None
        except (TypeError, ValueError):
            cvss_score = None

        published = data.get("Published", "") or data.get("published", "")
        if isinstance(published, str) and "T" in published:
            published = published.split("T")[0]

        refs: list[str] = []
        for ref in data.get("references", []):
            if isinstance(ref, str) and ref.startswith("http"):
                refs.append(ref)
            elif isinstance(ref, dict):
                url = ref.get("url", "")
                if url:
                    refs.append(url)

        affected: list[str] = []
        for cpe in data.get("vulnerable_configuration", [])[:10]:
            cpe_str = cpe if isinstance(cpe, str) else cpe.get("id", "")
            if cpe_str.startswith("cpe:"):
                parts = cpe_str.split(":")
                if len(parts) >= 5:
                    vendor  = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 else ""
                    entry   = f"{vendor} {product}"
                    if version and version not in ("*", "-"):
                        entry += f" {version}"
                    if entry not in affected:
                        affected.append(entry)

        return CVEDetail(
            cve_id            = cve_id,
            description       = data.get("summary", ""),
            cvss_score        = cvss_score,
            cvss_vector       = data.get("cvss-vector"),
            severity          = self._score_to_severity(cvss_score),
            published_date    = published,
            references        = refs[:5],
            exploit_available = False,
            affected_products = affected[:5],
            source            = "circl.lu",
        )

    # ── Private: NVD API ────────────────────────────────────────────────────

    async def _lookup_nvd(self, cve_id: str) -> Optional[CVEDetail]:
        """GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}"""
        await self._limiter.wait("nvd", self.NVD_RATE)
        try:
            resp = await self._client.get(
                self.NVD_BASE,
                params={"cveId": cve_id},
                timeout=15.0,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        return self._parse_nvd(vulns[0].get("cve", {}))

    def _parse_nvd(self, cve: dict) -> Optional[CVEDetail]:
        """
        Parse NVD 2.0 API CVE object.
        Schema: id, descriptions[], metrics.cvssMetricV31[],
                published, references[], configurations
        """
        cve_id = cve.get("id", "").upper()
        if not cve_id:
            return None

        # Description — prefer English
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS — prefer v3.1, then v3.0, then v2
        cvss_score:  Optional[float] = None
        cvss_vector: Optional[str]   = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                cvss_data   = metrics[0].get("cvssData", {})
                cvss_score  = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break

        published = cve.get("published", "")
        if "T" in published:
            published = published.split("T")[0]

        refs = [
            r["url"] for r in cve.get("references", [])
            if r.get("url", "").startswith("http")
        ][:5]

        return CVEDetail(
            cve_id            = cve_id,
            description       = desc,
            cvss_score        = cvss_score,
            cvss_vector       = cvss_vector,
            severity          = self._score_to_severity(cvss_score),
            published_date    = published,
            references        = refs,
            exploit_available = False,
            affected_products = [],
            source            = "nvd",
        )

    def _score_to_severity(self, score: Optional[float]) -> str:
        if score is None:
            return "none"
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0.0:  return "low"
        return "none"
