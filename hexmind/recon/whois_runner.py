"""Whois runner: regex-based field extraction for domain and IP whois output."""

from __future__ import annotations

import re

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class WhoisRunner(BaseRunner):
    """Runs whois and extracts structured registration data via regex."""

    name            = "whois"
    binary          = "whois"
    default_timeout = 30

    SAMPLE_OUTPUT: str = """\
Domain Name: EXAMPLE.COM
Registrar: GoDaddy.com, LLC
Creation Date: 2019-03-12T10:00:00Z
Registry Expiry Date: 2025-03-12T10:00:00Z
Updated Date: 2023-01-01T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
Registrant Organization: Example Corp
Registrant Country: US
Abuse Contact Email: abuse@godaddy.com
"""

    def build_command(self, target: str, flags: dict) -> list[str]:
        return ["whois", target]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Extract key fields from whois output using regex.

        Field extraction is case-insensitive and handles multiple label
        variations (e.g. 'Creation Date' / 'created').

        Returns dict with these keys (None if not found):
          registrar, creation_date, expiry_date, updated_date,
          name_servers (list[str]), status (list[str]),
          registrant_org, registrant_country,
          abuse_email, netname, org, asn, cidr
        """
        def _find(patterns: list[str], text: str) -> str | None:
            for pat in patterns:
                m = re.search(
                    rf"^\s*{pat}\s*[:\s]+(.+)$", text,
                    re.IGNORECASE | re.MULTILINE,
                )
                if m:
                    return m.group(1).strip()
            return None

        def _find_all(patterns: list[str], text: str) -> list[str]:
            results = []
            for pat in patterns:
                matches = re.findall(
                    rf"^\s*{pat}\s*[:\s]+(.+)$", text,
                    re.IGNORECASE | re.MULTILINE,
                )
                results.extend(m.strip() for m in matches)
            return list(dict.fromkeys(results))  # deduplicate, preserve order

        return {
            "registrar":          _find(
                ["Registrar", "registrar"], raw),
            "creation_date":      _find(
                ["Creation Date", "created", "Created On"], raw),
            "expiry_date":        _find(
                ["Registry Expiry Date", "Expiry Date",
                 "Expiration Date", "expires"], raw),
            "updated_date":       _find(
                ["Updated Date", "last-modified", "Last Updated"], raw),
            "name_servers":       _find_all(
                ["Name Server", "nserver"], raw),
            "status":             _find_all(
                ["Domain Status", "Status", "status"], raw),
            "registrant_org":     _find(
                ["Registrant Organization", "Registrant Org",
                 "org-name"], raw),
            "registrant_country": _find(
                ["Registrant Country", "country"], raw),
            "abuse_email":        _find(
                ["Abuse Contact Email", "OrgAbuseEmail",
                 "abuse-mailbox"], raw),
            # IP WHOIS fields
            "netname":            _find(["NetName", "netname"], raw),
            "org":                _find(["OrgName", "org"], raw),
            "asn":                _find(["OriginAS", "ASNumber", "origin"], raw),
            "cidr":               _find(["CIDR", "inetnum"], raw),
        }
