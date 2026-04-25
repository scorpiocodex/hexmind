"""
Converts structured tool output directly to FindingData objects.
These bypass the AI — the tools already identified them.
"""

from __future__ import annotations

from hexmind.db.schemas import FindingData


def nikto_to_findings(
    nikto_parsed: dict, target: str
) -> list[FindingData]:
    """Convert nikto parsed_output vulnerabilities to FindingData list."""
    findings: list[FindingData] = []
    vulns = nikto_parsed.get("vulnerabilities", [])

    for vuln in vulns:
        desc = vuln.get("description", "").strip()
        if not desc:
            continue

        url    = vuln.get("url", "")
        osvdb  = vuln.get("osvdb_id", "")
        method = vuln.get("method", "GET")

        desc_lower = desc.lower()
        if any(k in desc_lower for k in [
            "remote code execution", "rce", "sql injection",
            "command injection", "arbitrary code", "file upload",
        ]):
            severity = "high"
        elif any(k in desc_lower for k in [
            "xss", "cross-site scripting", "directory traversal",
            "path traversal", "file inclusion", "csrf",
            "information disclosure", "admin", "login",
            "default password", "default credential",
        ]):
            severity = "medium"
        elif any(k in desc_lower for k in [
            "version", "server", "banner", "header",
            "cookie", "outdated", "deprecated",
        ]):
            severity = "low"
        else:
            severity = "medium"

        component   = f"{target}:{url}" if url else target
        exploit     = f"{method} {url}" if url else method
        remediation = (
            f"Review and remediate this nikto finding. "
            f"Consult the nikto documentation and OSVDB {osvdb} for details."
            if osvdb else
            "Review and remediate this nikto finding."
        )

        findings.append(FindingData(
            severity          = severity,
            category          = "vulnerability",
            title             = f"Nikto: {desc[:80]}",
            description       = desc,
            affected_component= component,
            cve_ids           = [],
            exploit_notes     = exploit,
            remediation       = remediation,
            references        = [
                f"https://www.osvdb.org/{osvdb}" if osvdb else ""
            ],
            confidence_score  = 0.85,
        ))

    return findings


def dig_to_findings(
    dig_parsed: dict, target: str
) -> list[FindingData]:
    """Convert dig parsed_output email security gaps to FindingData."""
    missing = dig_parsed.get("missing_email_security", [])
    if not missing:
        return []

    missing_str = ", ".join(missing)

    spf_line   = "\n- SPF: Add a TXT record: v=spf1 ... ~all"   if "SPF"   in missing else ""
    dmarc_line = "\n- DMARC: Add: _dmarc TXT v=DMARC1; p=reject; rua=mailto:..." if "DMARC" in missing else ""
    dkim_line  = "\n- DKIM: Configure your mail server to sign with DKIM"          if "DKIM"  in missing else ""

    return [FindingData(
        severity          = "info",
        category          = "recon",
        title             = f"Missing Email Security: {missing_str}",
        description       = (
            f"The domain {target} is missing the following email security "
            f"records: {missing_str}. Without these records, attackers can "
            f"spoof emails from this domain to conduct phishing attacks."
        ),
        affected_component= f"DNS:{target}",
        cve_ids           = [],
        exploit_notes     = (
            f"An attacker can send emails that appear to originate from "
            f"{target} with no technical controls preventing it."
        ),
        remediation       = (
            f"Configure the following DNS records for {target}:"
            + spf_line + dmarc_line + dkim_line
        ),
        references        = [
            "https://www.dmarcanalyzer.com/how-to-create-a-dmarc-record/"
        ],
        confidence_score  = 0.99,
    )]


def curl_to_findings(
    curl_parsed: dict, target: str
) -> list[FindingData]:
    """Convert curl header analysis to findings. Only if >= 3 headers missing."""
    missing   = curl_parsed.get("missing_security_headers", [])
    if len(missing) < 3:
        return []

    info_disc = curl_parsed.get("info_disclosure_headers", {})
    server    = curl_parsed.get("server", "")
    findings: list[FindingData] = []

    missing_count = len(missing)
    missing_display = ", ".join(missing[:5]) + (
        f" and {missing_count - 5} more" if missing_count > 5 else ""
    )

    findings.append(FindingData(
        severity          = "medium",
        category          = "misconfiguration",
        title             = "Missing HTTP Security Headers",
        description       = (
            f"The web server at {target} is missing {missing_count} security "
            f"headers: {missing_display}. These headers protect against "
            f"clickjacking, XSS, MIME sniffing, and information disclosure."
        ),
        affected_component= f"HTTP:{target}",
        cve_ids           = [],
        exploit_notes     = (
            "Missing security headers allow: clickjacking (no X-Frame-Options), "
            "XSS (no CSP), MIME sniffing (no X-Content-Type-Options)."
        ),
        remediation       = (
            "Add these headers to the web server configuration:\n"
            "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "  Content-Security-Policy: default-src 'self'\n"
            "  X-Frame-Options: SAMEORIGIN\n"
            "  X-Content-Type-Options: nosniff\n"
            "  Referrer-Policy: strict-origin-when-cross-origin"
        ),
        references        = ["https://owasp.org/www-project-secure-headers/"],
        confidence_score  = 0.99,
    ))

    if info_disc:
        exposed = ", ".join(f"{k}: {v}" for k, v in info_disc.items())
        findings.append(FindingData(
            severity          = "low",
            category          = "exposure",
            title             = "Server Version Information Disclosed",
            description       = (
                f"The server reveals version information in HTTP headers: "
                f"{exposed}. This helps attackers identify specific "
                f"vulnerabilities for the detected software version."
            ),
            affected_component= f"HTTP:{target}",
            cve_ids           = [],
            exploit_notes     = (
                f"Version disclosure allows targeted vulnerability research. "
                f"Server: {server}"
            ),
            remediation       = (
                "For Apache: Set 'ServerTokens Prod' and 'ServerSignature Off'.\n"
                "For PHP: Set 'expose_php = Off' in php.ini."
            ),
            references        = [],
            confidence_score  = 0.99,
        ))

    return findings
