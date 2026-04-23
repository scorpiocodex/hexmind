"""Dig DNS runner: queries A, AAAA, MX, NS, TXT, SOA, and PTR records."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime

from hexmind.recon.base_runner import BaseRunner, RunnerResult


class DigRunner(BaseRunner):
    """Runs multiple dig queries and aggregates DNS record results."""

    name            = "dig"
    binary          = "dig"
    default_timeout = 15

    SAMPLE_OUTPUT: str = "93.184.216.34\n"

    def build_command(self, target: str, flags: dict) -> list[str]:
        """Not used directly — run() is overridden. Required by ABC."""
        return ["dig", "+short", target, "A"]

    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Not used directly — aggregation is done inside run()."""
        return {"raw": raw}

    async def run(
        self,
        target:  str,
        flags:   dict = {},
        timeout: int | None = None,
    ) -> RunnerResult:
        """Run multiple dig queries in sequence and aggregate results.

        For domain targets, queries: A, AAAA, MX, NS, TXT, SOA
        For IP targets, queries:    PTR (reverse lookup)

        Returns RunnerResult with parsed_output containing:
          a_records, aaaa_records, mx_records, ns_records,
          txt_records, soa_record, ptr_record,
          has_spf, has_dmarc, has_dkim,
          missing_email_security, raw_per_type
        """
        if not self.is_available():
            return RunnerResult(
                tool_name=self.name,
                command_run="dig",
                raw_output="",
                parsed_output={},
                exit_code=-1,
                duration_ms=0,
                error="Binary 'dig' not found. Install: sudo apt install dnsutils",
            )

        start   = time.monotonic()
        started = datetime.utcnow()

        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            query_types: dict[str, list[str]] = {"PTR": ["-x", target]}
        else:
            query_types = {
                "A":    ["+short", target, "A"],
                "AAAA": ["+short", target, "AAAA"],
                "MX":   ["+short", target, "MX"],
                "NS":   ["+short", target, "NS"],
                "TXT":  ["+short", target, "TXT"],
                "SOA":  ["+short", target, "SOA"],
            }

        raw_per_type: dict[str, str] = {}
        t_out = timeout or self.default_timeout

        for rtype, args in query_types.items():
            cmd = ["dig"] + args
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=t_out
                )
                raw_per_type[rtype] = stdout.decode(
                    "utf-8", errors="replace"
                ).strip()
            except asyncio.TimeoutError:
                raw_per_type[rtype] = ""
            except Exception as e:
                raw_per_type[rtype] = f"error: {e}"

        elapsed = int((time.monotonic() - start) * 1000)
        all_raw = "\n".join(
            f";; {k}\n{v}" for k, v in raw_per_type.items()
        )
        parsed  = self._aggregate(raw_per_type, is_ip)

        return RunnerResult(
            tool_name=self.name,
            command_run=f"dig [multiple queries for {target}]",
            raw_output=all_raw,
            parsed_output=parsed,
            exit_code=0,
            duration_ms=elapsed,
            started_at=started,
        )

    def _aggregate(
        self, raw_per_type: dict[str, str], is_ip: bool
    ) -> dict:
        def lines(key: str) -> list[str]:
            return [
                ln.strip()
                for ln in raw_per_type.get(key, "").splitlines()
                if ln.strip() and not ln.startswith(";")
            ]

        txt_records = lines("TXT")
        has_spf    = any("v=spf1"   in t.lower() for t in txt_records)
        has_dmarc  = any("v=dmarc1" in t.lower() for t in txt_records)
        has_dkim   = any("v=dkim1"  in t.lower() for t in txt_records)

        soa_lines = lines("SOA")
        ptr_lines = lines("PTR")

        return {
            "a_records":    lines("A"),
            "aaaa_records": lines("AAAA"),
            "mx_records":   lines("MX"),
            "ns_records":   lines("NS"),
            "txt_records":  txt_records,
            "soa_record":   soa_lines[0] if soa_lines else None,
            "ptr_record":   ptr_lines[0] if is_ip and ptr_lines else None,
            "has_spf":      has_spf,
            "has_dmarc":    has_dmarc,
            "has_dkim":     has_dkim,
            "missing_email_security": [
                name for name, present in [
                    ("SPF",   has_spf),
                    ("DMARC", has_dmarc),
                    ("DKIM",  has_dkim),
                ]
                if not present
            ],
            "raw_per_type": raw_per_type,
        }
