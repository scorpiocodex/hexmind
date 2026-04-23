"""SSL/TLS scanner runner: sslscan XML output parsed into cipher and cert info."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class SSLRunner(BaseRunner):
    """Runs sslscan and parses cipher suites, protocol versions, and certificate data."""

    name            = "sslscan"
    binary          = "sslscan"
    default_timeout = 60

    WEAK_PROTOCOLS: frozenset[str] = frozenset({"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"})
    WEAK_CIPHERS:   frozenset[str] = frozenset({"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON"})

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Build sslscan command with XML output to temp file.

        flags keys:
          port (str): target port — default "443"
        """
        self._tmp_xml: str = tempfile.mktemp(
            prefix="hexmind_ssl_", suffix=".xml"
        )
        port = str(flags.get("port", "443"))
        return [
            "sslscan",
            f"--xml={self._tmp_xml}",
            "--no-colour",
            f"{target}:{port}",
        ]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse sslscan XML output.

        Returns:
          protocol_versions: dict[str, bool]   e.g. {"TLSv1.0": True, ...}
          ciphers: list[{name, bits, curve, strength}]
          certificate: {subject, issuer, not_before, not_after,
                        days_until_expiry, self_signed, sig_algorithm,
                        expired, expiring_soon}
          weak_protocols: list[str]
          weak_ciphers: list[str]
          issues: list[str]   — human-readable weakness descriptions
          grade: str          — A/B/C/D/F heuristic
        """
        import xmltodict

        xml_path = getattr(self, "_tmp_xml", None)
        xml_raw  = ""

        if xml_path and Path(xml_path).exists():
            try:
                xml_raw = Path(xml_path).read_text(encoding="utf-8")
            except Exception:
                pass
            finally:
                try:
                    os.unlink(xml_path)
                except Exception:
                    pass

        if not xml_raw:
            return self._empty_result()

        try:
            data = xmltodict.parse(xml_raw)
        except Exception:
            return self._empty_result()

        # sslscan XML root varies by version: <document><ssltest> or just <ssltest>
        if "ssltest" in data:
            scan = data["ssltest"]
        elif "document" in data:
            inner = data["document"]
            scan  = inner.get("ssltest", inner)
        else:
            scan = {}

        # Protocol versions
        protocols_raw = scan.get("protocol", [])
        if isinstance(protocols_raw, dict):
            protocols_raw = [protocols_raw]
        protocol_versions: dict[str, bool] = {}
        for p in protocols_raw:
            ptype    = p.get("@type", "")
            pversion = p.get("@version", "")
            name     = f"{ptype}{pversion}"
            enabled  = p.get("@enabled", "0") == "1"
            protocol_versions[name] = enabled

        weak_protos = [
            p for p, enabled in protocol_versions.items()
            if enabled and p in self.WEAK_PROTOCOLS
        ]

        # Ciphers
        ciphers_raw  = scan.get("cipher", [])
        if isinstance(ciphers_raw, dict):
            ciphers_raw = [ciphers_raw]
        ciphers:      list[dict] = []
        weak_ciphers: list[str]  = []
        for c in ciphers_raw:
            name   = c.get("@cipher", c.get("@sslversion", ""))
            bits   = c.get("@bits",   "")
            status = c.get("@strength", c.get("@status", ""))
            ciphers.append({
                "name":     name,
                "bits":     bits,
                "curve":    c.get("@curve", ""),
                "strength": status,
            })
            if any(w in name.upper() for w in self.WEAK_CIPHERS):
                weak_ciphers.append(name)

        # Certificate
        cert_raw  = scan.get("certificate") or {}
        cert_info = self._parse_cert(cert_raw)

        # Build issues list
        issues: list[str] = []
        for p in weak_protos:
            issues.append(f"Weak protocol enabled: {p}")
        for c in weak_ciphers[:5]:
            issues.append(f"Weak cipher offered: {c}")
        if cert_info.get("expired"):
            issues.append("Certificate is EXPIRED")
        elif cert_info.get("expiring_soon"):
            days = cert_info.get("days_until_expiry", 0)
            issues.append(f"Certificate expiring in {days} days")
        if cert_info.get("self_signed"):
            issues.append("Certificate is self-signed")

        grade = self._grade(weak_protos, weak_ciphers, cert_info)

        return {
            "protocol_versions": protocol_versions,
            "ciphers":           ciphers,
            "certificate":       cert_info,
            "weak_protocols":    weak_protos,
            "weak_ciphers":      weak_ciphers[:10],
            "issues":            issues,
            "grade":             grade,
        }

    def _parse_cert(self, cert: dict) -> dict:
        subject    = cert.get("subject",      "")
        issuer     = cert.get("issuer",       "")
        not_after  = cert.get("not-after",    cert.get("expired",  ""))
        not_before = cert.get("not-before",   cert.get("issued",   ""))
        sig_alg    = cert.get("signature-algorithm", "")

        days:          int | None = None
        expired        = False
        expiring_soon  = False
        try:
            exp_dt = datetime.strptime(
                not_after.strip(), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days          = (exp_dt - datetime.now(timezone.utc)).days
            expired       = days < 0
            expiring_soon = 0 <= days < 30
        except Exception:
            pass

        self_signed = bool(subject and issuer and subject == issuer)

        return {
            "subject":           subject,
            "issuer":            issuer,
            "not_before":        not_before,
            "not_after":         not_after,
            "days_until_expiry": days,
            "self_signed":       self_signed,
            "sig_algorithm":     sig_alg,
            "expired":           expired,
            "expiring_soon":     expiring_soon,
        }

    def _grade(
        self,
        weak_protos:  list[str],
        weak_ciphers: list[str],
        cert:         dict,
    ) -> str:
        score = 100
        score -= len(weak_protos)  * 20
        score -= len(weak_ciphers) * 5
        if cert.get("expired"):
            score -= 40
        if cert.get("self_signed"):
            score -= 20
        if cert.get("expiring_soon"):
            score -= 10
        if score >= 90: return "A"
        if score >= 70: return "B"
        if score >= 50: return "C"
        if score >= 30: return "D"
        return "F"

    def _empty_result(self) -> dict:
        return {
            "protocol_versions": {}, "ciphers": [],
            "certificate": {}, "weak_protocols": [],
            "weak_ciphers": [], "issues": [], "grade": "?",
        }
