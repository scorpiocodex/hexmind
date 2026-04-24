"""Curl HTTP header runner: extracts server info and security header presence."""

from __future__ import annotations

import re

from hexmind.recon.base_runner import BaseRunner, RunnerResult

SECURITY_HEADERS: list[str] = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

LEGACY_HEADERS: list[str] = [
    "x-xss-protection",      # deprecated, flag if present
    "x-powered-by",          # info disclosure
    "server",                 # info disclosure
    "x-aspnet-version",       # info disclosure
    "x-aspnetmvc-version",    # info disclosure
]


class CurlRunner(BaseRunner):
    """Runs curl -sI to capture response headers and flags missing security headers."""

    name            = "curl"
    binary          = "curl"
    default_timeout = 30

    SAMPLE_OUTPUT: str = """\
HTTP/2 200
server: Apache/2.4.49
x-powered-by: PHP/7.2.5
content-type: text/html; charset=UTF-8
"""

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Build curl command to fetch HTTP headers only.

        Prepends https:// if no scheme present.
        Follows redirects; appends write-out for FINAL_URL and HTTP_CODE.
        """
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        return [
            "curl",
            "-sI",
            "-L",
            "-k",
            "--connect-timeout", "10",
            "--max-time", "15",
            "--max-redirs", "5",
            "--user-agent",
            "Mozilla/5.0 (compatible; HexMind/0.1 SecurityScanner)",
            "-w", "\\nFINAL_URL:%{url_effective}\\nHTTP_CODE:%{http_code}",
            url,
        ]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse curl -sI header output.

        Returns:
          status_code (int), final_url (str),
          server (str|None), x_powered_by (str|None),
          present_security_headers (list[str]),
          missing_security_headers (list[str]),
          info_disclosure_headers (dict[str, str]),
          legacy_headers (dict[str, str]),
          all_headers (dict[str, str]),
          security_header_score (int), security_header_max (int)
        """
        lines: list[str]     = raw.splitlines()
        all_headers: dict[str, str] = {}
        status_code: int     = 0
        final_url:   str     = ""

        for line in lines:
            if line.startswith("FINAL_URL:"):
                final_url = line.split(":", 1)[1].strip()
            elif line.startswith("HTTP_CODE:"):
                try:
                    status_code = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass

        for line in lines:
            if ":" in line and not line.startswith(
                ("HTTP", "FINAL_URL", "HTTP_CODE")
            ):
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key:
                    all_headers[key] = val

        if status_code == 0:
            for line in lines:
                m = re.match(r"^HTTP/[\d.]+ (\d{3})", line)
                if m:
                    status_code = int(m.group(1))
                    break

        present_sec = [h for h in SECURITY_HEADERS if h in all_headers]
        missing_sec = [h for h in SECURITY_HEADERS if h not in all_headers]
        info_disc   = {
            h: all_headers[h]
            for h in [
                "server", "x-powered-by",
                "x-aspnet-version", "x-aspnetmvc-version",
            ]
            if h in all_headers
        }
        legacy = {
            h: all_headers[h]
            for h in LEGACY_HEADERS
            if h in all_headers
        }

        return {
            "status_code":              status_code,
            "final_url":                final_url,
            "server":                   all_headers.get("server"),
            "x_powered_by":             all_headers.get("x-powered-by"),
            "present_security_headers": present_sec,
            "missing_security_headers": missing_sec,
            "info_disclosure_headers":  info_disc,
            "legacy_headers":           legacy,
            "all_headers":              all_headers,
            "security_header_score":    len(present_sec),
            "security_header_max":      len(SECURITY_HEADERS),
        }
