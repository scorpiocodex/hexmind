"""Prompt templates and tool-output formatters for AI context construction."""

from __future__ import annotations

MAX_TOOL_CHARS: int = 4000
MAX_CONTEXT_TOKENS: int = 28000

SYSTEM_PROMPT: str = (
    "You are HexMind, an expert penetration tester and security analyst with 20 years "
    "of experience. You analyze reconnaissance data and identify vulnerabilities with "
    "precision. Always respond with structured findings in the specified XML format. "
    "Be specific, cite CVE IDs where applicable, and suggest realistic exploits and "
    "remediations. You may request additional tool runs using <tool_request> tags, "
    "web searches using <search_request> tags, and CVE details using <cve_lookup> tags."
)

ANALYSIS_PROMPT_TEMPLATE: str = """\
TARGET: {target}
SCAN PROFILE: {profile}
ITERATION: {iteration} of {max_iterations}

=== TOOL RESULTS ===
{tool_outputs}

=== PREVIOUS FINDINGS ===
{previous_findings_summary}

=== TASK ===
1. Analyze all tool outputs for security vulnerabilities.
2. For each finding output a <finding> block with: severity, category, title,
   description, component, cves, exploit, remediation, confidence.
3. Request additional tool runs via <tool_request> if data gaps exist.
4. Request CVE/exploit context via <search_request> or <cve_lookup> tags.
5. On the final iteration produce an executive summary and risk_score (0-100).
"""

FINAL_SYNTHESIS_PROMPT: str = """\
All recon iterations are complete. Produce:
1. An executive summary paragraph.
2. A risk_score integer (0-100) based on finding severity distribution.
3. A prioritised remediation roadmap.
"""


def format_nmap_for_prompt(result: dict) -> str:
    """Format a parsed nmap result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")


def format_nikto_for_prompt(result: dict) -> str:
    """Format a parsed nikto result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")


def format_whois_for_prompt(result: dict) -> str:
    """Format a parsed whois result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")


def format_dig_for_prompt(result: dict) -> str:
    """Format a parsed dig result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")


def format_curl_for_prompt(result: dict) -> str:
    """Format a parsed curl header result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")


def format_ssl_for_prompt(result: dict) -> str:
    """Format a parsed sslscan result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")


def format_whatweb_for_prompt(result: dict) -> str:
    """Format a parsed whatweb result dict into a compact prompt-ready string."""
    raise NotImplementedError("TODO: implement")
