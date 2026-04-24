"""Prompt templates and tool-output formatters for AI context construction."""

from __future__ import annotations

# Token budget constants
MAX_TOOL_CHARS:     int = 4000    # max chars per tool block in prompt
MAX_CONTEXT_TOKENS: int = 28000   # leave ~4k headroom for response

# ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT: str = """\
You are HexMind, an expert penetration tester and offensive security \
analyst with 20 years of experience across web applications, network \
infrastructure, and cloud environments.

ROLE:
You analyze reconnaissance data collected by automated tools and \
identify security vulnerabilities with surgical precision. You cite \
real CVE IDs, reference actual exploit techniques, and provide \
actionable remediation steps.

OUTPUT FORMAT:
Structure ALL findings using this exact XML:

<finding>
  <severity>CRITICAL|HIGH|MEDIUM|LOW|INFO</severity>
  <category>vulnerability|misconfiguration|exposure|recon</category>
  <title>Short descriptive title (max 80 chars)</title>
  <description>Detailed technical description</description>
  <component>Affected service, version, or port (e.g. Apache/2.4.49:80)</component>
  <cves>CVE-2021-41773, CVE-2021-42013</cves>
  <exploit>Concrete exploit technique or PoC description</exploit>
  <remediation>Specific fix with configuration examples where possible</remediation>
  <confidence>0.0-1.0</confidence>
</finding>

SEVERITY DEFINITIONS (CVSS-aligned):
- CRITICAL (9.0-10.0): Remote code execution, authentication bypass, \
  unauthenticated data breach
- HIGH (7.0-8.9): Significant data exposure, privilege escalation, \
  SQLi, XXE, SSRF
- MEDIUM (4.0-6.9): Information disclosure, missing security controls, \
  XSS, CSRF
- LOW (0.1-3.9): Minor misconfigurations, verbose error messages, \
  deprecated but not immediately exploitable
- INFO: Reconnaissance data, technology fingerprinting, no immediate risk

REQUESTING ADDITIONAL TOOL RUNS:
If you need more data, emit exactly:
<tool_request>
  <tool>nmap|whois|dig|curl|whatweb|sslscan|nikto|gobuster</tool>
  <args>-sV -p 3306,5432,27017 {target}</args>
  <reason>Brief explanation of why you need this data</reason>
</tool_request>

REQUESTING WEB SEARCHES:
<search_request>
  <query>Apache 2.4.49 CVE-2021-41773 exploit</query>
</search_request>

REQUESTING CVE LOOKUPS:
<cve_lookup>
  <cve_id>CVE-2021-41773</cve_id>
</cve_lookup>

RULES:
1. Never request the same tool+args combination twice.
2. Only request tools that exist in the allowed list above.
3. Use {target} as a placeholder for the target in tool args.
4. Assign confidence scores honestly — 0.9+ only when evidence is \
   unambiguous.
5. Confidence scores MUST be decimal format between 0.0 and 1.0. \
   Never use percentage format (write 0.85 not 85%).
6. Only cite CVE IDs you are certain exist. If you are not certain \
   of the exact CVE ID for a vulnerability, leave <cves></cves> empty \
   and describe the vulnerability class in <description> instead. \
   A missing CVE is always better than a fabricated one.
7. Match CVEs precisely to the detected service. Apache httpd and \
   Apache Struts are DIFFERENT products. Only assign a CVE to a \
   service if that CVE specifically affects that exact software. \
   Never cross-assign CVEs between related but distinct products.
8. CVE IDs are version-specific — apply them ONLY to exact \
   affected versions: \
   - Verify the detected version falls within the CVE's EXACT \
     affected range before citing it. If uncertain, omit the CVE. \
   - CVE-2021-41773 → Apache 2.4.49 ONLY. Not 2.4.7, not 2.4.50. \
   - CVEs with very old years (pre-2010) assigned at 90%+ confidence \
     to modern software are almost certainly hallucinations. \
   - If you cannot name a real, verifiable CVE for a finding, leave \
     <cves></cves> empty. A finding without a CVE is correct. \
     A finding with a fabricated CVE is harmful. \
   - Never invent CVE IDs to fill the field. If unsure, leave empty.
9. <risk_score> MUST be a plain integer 0-100. No decimals. No CVSS \
   format. No text. No units. \
   CORRECT: <risk_score>65</risk_score> \
   WRONG (will be misread): <risk_score>6.5</risk_score> \
   WRONG (will be misread): <risk_score>8.5 (High)</risk_score> \
   If your CVSS score is 6.5, multiply by 10 and emit 65.
10. Finding titles must NOT be wrapped in quotation marks. \
   CORRECT: <title>Apache 2.4.7 Directory Traversal</title> \
   WRONG:   <title>"Apache 2.4.7 Directory Traversal"</title>
11. On the final iteration, produce an <executive_summary> and \
   <risk_score> (0-100 integer).

<executive_summary>3-paragraph summary of overall risk posture</executive_summary>
<risk_score>75</risk_score>
"""

# ── ANALYSIS PROMPT TEMPLATE ──────────────────────────────────────────────────
# Variables: {target} {profile} {iteration} {max_iterations}
#            {tool_results_text} {previous_section} {search_section}
#            {iteration_instruction} {final_instruction}
ANALYSIS_PROMPT_TEMPLATE: str = """\
TARGET: {target}
SCAN PROFILE: {profile}
ANALYSIS PASS: {iteration} of {max_iterations}

━━━━ RECONNAISSANCE DATA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{tool_results_text}

{previous_section}{search_section}\
━━━━ INSTRUCTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Analyze every section of the reconnaissance data above.

Step 1 — Service fingerprinting:
  Identify every service, version, and technology stack component. \
Flag any outdated or known-vulnerable versions. \
Pay careful attention to exact product names — Apache HTTP Server \
and Apache Struts are completely different products and must not \
have each other's CVEs assigned to them.

Step 2 — Vulnerability mapping:
  For each identified service/version, recall known CVEs and \
  vulnerabilities. Produce a <finding> block for each confirmed issue.

Step 3 — Attack chain analysis:
  Identify how multiple findings could be chained into a complete \
  attack path. Note any pivot opportunities.

Step 4 — Data gaps:
  If critical information is missing that would change your risk \
  assessment, emit <tool_request> or <search_request> blocks.
  {iteration_instruction}

Step 5 — Output:
  Emit all <finding> blocks. Then emit any <tool_request>, \
  <search_request>, or <cve_lookup> blocks.
  {final_instruction}
"""

# ── FINAL SYNTHESIS PROMPT ────────────────────────────────────────────────────
FINAL_SYNTHESIS_PROMPT: str = """\
This is the FINAL analysis pass. Do not emit any <tool_request> blocks.

Based on all findings gathered across {iteration} analysis passes, \
produce:

1. <executive_summary>
   Paragraph 1: Overall risk posture and most critical issues.
   Paragraph 2: Attack paths and exploit chains identified.
   Paragraph 3: Recommended immediate actions (top 3 priorities).
</executive_summary>

2. <risk_score>{risk_hint}</risk_score>
   Integer 0-100 reflecting overall exploitability and impact.
   (Current preliminary score based on findings: {risk_hint})

3. A prioritized remediation roadmap — emit one <finding> per \
   remediation item ordered by priority (most critical first), \
   using the remediation field only.

All previous findings are confirmed. Focus on synthesis, not \
re-analysis.
"""


# ── PER-ITERATION INSTRUCTION STRINGS ────────────────────────────────────────
def _iteration_instruction(iteration: int, max_iterations: int) -> str:
    if iteration >= max_iterations:
        return (
            "This is the FINAL pass — do NOT emit any tool requests. "
            "Produce complete findings and executive summary."
        )
    remaining = max_iterations - iteration
    return (
        f"You have {remaining} more pass(es) remaining. "
        "Request additional tools only if the gap is critical."
    )


def _final_instruction(iteration: int, max_iterations: int) -> str:
    if iteration >= max_iterations:
        return (
            "Also emit <executive_summary> and <risk_score> tags "
            "as this is the final pass."
        )
    return ""


# ── TRUNCATION HELPER ─────────────────────────────────────────────────────────
def _truncate(text: str, max_chars: int = MAX_TOOL_CHARS) -> str:
    """Keep first 60% + last 20% when text exceeds max_chars."""
    if len(text) <= max_chars:
        return text
    keep_head = int(max_chars * 0.60)
    keep_tail = int(max_chars * 0.20)
    dropped   = len(text) - keep_head - keep_tail
    return (
        text[:keep_head]
        + f"\n... [truncated {dropped} chars] ...\n"
        + text[-keep_tail:]
    )


# ── TOOL OUTPUT FORMATTERS ────────────────────────────────────────────────────

def format_nmap_for_prompt(result: dict) -> str:
    """Format a parsed nmap result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = []
    for p in result.get("ports", []):
        svc   = p.get("service_name",    "")
        prod  = p.get("service_product", "")
        ver   = p.get("service_version", "")
        extra = p.get("service_extra",   "")
        line  = f"  {p['port_id']}/{p['protocol']}  {p['state']}  {svc}"
        if prod or ver:
            line += f"  {prod} {ver}".rstrip()
        if extra:
            line += f"  ({extra})"
        lines.append(line)
        for s in p.get("scripts", []):
            if s.get("output"):
                lines.append(f"    [script:{s['id']}] {s['output'][:200]}")
    os_list = result.get("os_matches", [])
    if os_list:
        top = os_list[0]
        lines.append(f"  OS: {top['name']} ({top['accuracy']}% confidence)")
    vuln_scripts = result.get("vulnerable_scripts", [])
    if vuln_scripts:
        lines.append(f"  VULNERABLE scripts detected: {', '.join(vuln_scripts)}")
    if not lines:
        lines.append("  No open ports found.")
    return _truncate("\n".join(lines))


def format_whois_for_prompt(result: dict) -> str:
    """Format a parsed whois result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    fields = [
        ("Registrar",    result.get("registrar")),
        ("Created",      result.get("creation_date")),
        ("Expires",      result.get("expiry_date")),
        ("Org",          result.get("registrant_org")),
        ("Country",      result.get("registrant_country")),
        ("Name Servers", ", ".join(result.get("name_servers", [])[:4]) or None),
        ("ASN",          result.get("asn")),
        ("Netname",      result.get("netname")),
    ]
    lines = [f"  {k}: {v}" for k, v in fields if v]
    return _truncate("\n".join(lines)) if lines else "  No data.\n"


def format_dig_for_prompt(result: dict) -> str:
    """Format a parsed dig result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = []
    for rec_type in ("a_records", "aaaa_records", "mx_records",
                     "ns_records", "txt_records"):
        records = result.get(rec_type, [])
        if records:
            label = rec_type.replace("_records", "").upper()
            lines.append(f"  {label}: {', '.join(records[:5])}")
    soa = result.get("soa_record")
    if soa:
        lines.append(f"  SOA: {soa}")
    missing = result.get("missing_email_security", [])
    if missing:
        lines.append(f"  ⚠ Missing email security: {', '.join(missing)}")
    else:
        lines.append("  Email security: SPF/DMARC/DKIM all present")
    return _truncate("\n".join(lines)) if lines else "  No data.\n"


def format_curl_for_prompt(result: dict) -> str:
    """Format a parsed curl header result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = [f"  HTTP Status: {result.get('status_code', '?')}"]
    if result.get("server"):
        lines.append(f"  Server: {result['server']}")
    if result.get("x_powered_by"):
        lines.append(
            f"  X-Powered-By: {result['x_powered_by']} ← version disclosure"
        )
    missing = result.get("missing_security_headers", [])
    if missing:
        lines.append(f"  Missing security headers ({len(missing)}):")
        for h in missing:
            lines.append(f"    - {h}")
    present = result.get("present_security_headers", [])
    if present:
        lines.append(f"  Present: {', '.join(present)}")
    disc = result.get("info_disclosure_headers", {})
    if disc:
        lines.append("  Info disclosure headers:")
        for k, v in disc.items():
            lines.append(f"    {k}: {v}")
    return _truncate("\n".join(lines))


def format_ssl_for_prompt(result: dict) -> str:
    """Format a parsed sslscan result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = [f"  Grade: {result.get('grade', '?')}"]
    protos  = result.get("protocol_versions", {})
    enabled = [p for p, on in protos.items() if on]
    if enabled:
        lines.append(f"  Enabled protocols: {', '.join(enabled)}")
    weak_p = result.get("weak_protocols", [])
    if weak_p:
        lines.append(f"  ⚠ WEAK protocols: {', '.join(weak_p)}")
    weak_c = result.get("weak_ciphers", [])
    if weak_c:
        lines.append(f"  ⚠ Weak ciphers: {', '.join(weak_c[:5])}")
    cert = result.get("certificate", {})
    if cert:
        lines.append(f"  Certificate: {cert.get('subject', '?')}")
        lines.append(
            f"    Expires: {cert.get('not_after', '?')}"
            f" ({cert.get('days_until_expiry', '?')} days)"
        )
        if cert.get("self_signed"):
            lines.append("    ⚠ SELF-SIGNED certificate")
        if cert.get("expired"):
            lines.append("    ⚠ EXPIRED certificate")
    issues = result.get("issues", [])
    if issues:
        lines.append("  Issues:")
        for iss in issues:
            lines.append(f"    - {iss}")
    return _truncate("\n".join(lines))


def format_whatweb_for_prompt(result: dict) -> str:
    """Format a parsed whatweb result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = [
        f"  HTTP Status: {result.get('http_status', '?')}",
        f"  Technologies detected ({result.get('plugin_count', 0)}):",
    ]
    for tech in result.get("technologies", []):
        name = tech.get("name", "")
        ver  = tech.get("version")
        line = f"    - {name}"
        if ver:
            line += f" {ver}"
        lines.append(line)
    interesting = result.get("interesting", [])
    if interesting:
        lines.append("  Notable:")
        for item in interesting:
            lines.append(f"    → {item}")
    return _truncate("\n".join(lines))


def format_nikto_for_prompt(result: dict) -> str:
    """Format a parsed nikto result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = [
        f"  Target: {result.get('target_hostname', '?')}:"
        f"{result.get('target_port', '?')}",
        f"  Total findings: {result.get('total_findings', 0)}",
    ]
    if result.get("server_banner"):
        lines.append(f"  Server banner: {result['server_banner']}")
    for v in result.get("vulnerabilities", [])[:20]:
        desc  = v.get("description", "")[:120]
        url   = v.get("url", "")
        osvdb = v.get("osvdb_id", "")
        lines.append(f"  [{osvdb}] {v.get('method', 'GET')} {url}: {desc}")
    return _truncate("\n".join(lines))


def format_gobuster_for_prompt(result: dict) -> str:
    """Format a parsed gobuster result dict into a compact prompt-ready string."""
    if not result:
        return "  No data.\n"
    lines: list[str] = [f"  Total paths found: {result.get('total_found', 0)}"]
    for path in result.get("found_200", [])[:15]:
        lines.append(f"  [200] {path}")
    for path in result.get("redirects", [])[:5]:
        lines.append(f"  [30x] {path}")
    for path in result.get("forbidden_403", [])[:5]:
        lines.append(f"  [403] {path}")
    interesting = result.get("interesting", [])
    if interesting:
        lines.append(f"  ⚠ Interesting paths: {', '.join(interesting[:10])}")
    return _truncate("\n".join(lines))


# ── FORMATTER DISPATCH ────────────────────────────────────────────────────────
TOOL_FORMATTERS: dict[str, object] = {
    "nmap":     format_nmap_for_prompt,
    "whois":    format_whois_for_prompt,
    "dig":      format_dig_for_prompt,
    "curl":     format_curl_for_prompt,
    "sslscan":  format_ssl_for_prompt,
    "whatweb":  format_whatweb_for_prompt,
    "nikto":    format_nikto_for_prompt,
    "gobuster": format_gobuster_for_prompt,
}


def format_tool_result(tool_name: str, parsed: dict) -> str:
    """Dispatch to the correct formatter. Returns formatted text block."""
    fn = TOOL_FORMATTERS.get(tool_name)
    if fn:
        return fn(parsed)
    return f"  {str(parsed)[:MAX_TOOL_CHARS]}\n"
