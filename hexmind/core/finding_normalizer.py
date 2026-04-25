"""
Shared finding normalization utilities.
Used by both AgenticLoop (dedup) and FindingRepository (exists check)
to ensure identical title matching.
"""
import re


def normalize_finding_title(title: str) -> str:
    """
    Normalize a finding title for dedup comparison.
    MUST produce identical output for titles describing the same issue.
    """
    t = (title or "").strip().strip('"').strip("'").lower()

    # Iteratively strip parenthetical content (handles nesting)
    for _ in range(4):
        prev = t
        t = re.sub(r'\s*\([^()]*\)', '', t).strip()
        if t == prev:
            break

    # Strip orphaned paren chars
    t = t.replace('(', '').replace(')', '').strip()

    # Remove CVE IDs in the form "cve-XXXX-XXXXX"
    t = re.sub(r'\bcve-[\d-]+\b', '', t, flags=re.IGNORECASE).strip()

    # Strip orphaned "cve" token after CVE removal
    t = re.sub(r'\bcve\b', '', t).strip()

    # Normalize Apache product prefix variants
    t = re.sub(r'apache\s+\d+[\.\d]+\s*', 'apache ', t)
    t = re.sub(r'apache\s+http\s+server\s*', 'apache ', t)
    t = re.sub(r'apache\s+httpd\s*', 'apache ', t)

    # Normalize ALL "missing security headers" variants to one canonical form
    t = re.sub(
        r'(apache\s+)?(missing\s+(http\s+)?security\s+headers?)',
        'missing security headers',
        t,
    )

    # Strip common vulnerability type terms so CVE-named and type-named
    # findings for the same product normalize to the same key.
    # E.g. "apache cve-2019-12332" and "apache directory traversal" → "apache"
    t = re.sub(
        r'\b(directory|path)\s+traversal\b'
        r'|\bsql\s+injection\b'
        r'|\bxss\b|\bcross[- ]site\s+scripting\b'
        r'|\bremote\s+code\s+execution\b|\brce\b'
        r'|\bfile\s+inclusion\b|\bssrf\b'
        r'|\bopen\s+redirect\b|\bcsrf\b|\bxxe\b',
        '',
        t,
        flags=re.IGNORECASE,
    )
    # Clean stray punctuation left after term removal (e.g. "path traversal & rce")
    t = re.sub(r'\s*[&|]\s*', ' ', t)

    # Collapse whitespace
    t = re.sub(r'\s+', ' ', t).strip()
    return t


def normalize_component(component: str) -> str:
    """
    Normalize a component string for dedup comparison.
    Groups web server variants, DNS variants, SSH variants.
    """
    c = (component or "").lower().strip()
    if not c or c in ('—', '-'):
        return 'unknown'

    # Bridge-style: "http:hostname" → "http"
    c = re.sub(r'^(http|https|dns|email|ftp|smtp):[^\s]+', r'\1', c)

    # Strip Apache version strings
    c = re.sub(r'apache/[\d\.]+.*', 'apache', c)
    c = re.sub(r'apache\s+[\d\.]+.*', 'apache', c)
    c = re.sub(r'apache\s+http\s+server.*', 'apache', c)
    c = re.sub(r'apache\s+httpd.*', 'apache', c)

    c_stripped = (c.replace(' ', '')
                   .replace('(ubuntu)', '')
                   .replace('(debian)', '')
                   .strip())

    web_tokens = {
        'http', 'https', 'apache', 'nginx', 'iis',
        'lighttpd', 'caddy', 'tomcat', 'jetty',
    }
    if any(c_stripped.startswith(t) for t in web_tokens):
        return 'webserver'

    dns_tokens = {'dns', 'email', 'emailinfrastructure', 'mail'}
    if c_stripped in dns_tokens or 'email' in c_stripped:
        return 'dns'

    if 'ssh' in c_stripped or 'openssh' in c_stripped:
        return 'ssh'

    db_tokens = {
        'mysql', 'postgres', 'postgresql', 'mongodb',
        'redis', 'mssql', 'oracle', 'db',
    }
    if any(d in c_stripped for d in db_tokens):
        return 'db'

    return c_stripped or 'unknown'
