"""Async recon pipeline coordinator: manages tiered tool execution."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from hexmind.constants import RECON_TIERS, SCAN_PROFILES
from hexmind.recon.base_runner import RunnerResult
from hexmind.recon.curl_runner import CurlRunner
from hexmind.recon.dig_runner import DigRunner
from hexmind.recon.gobuster_runner import GobusterRunner
from hexmind.recon.nikto_runner import NiktoRunner
from hexmind.recon.nmap_runner import NmapRunner
from hexmind.recon.ssl_runner import SSLRunner
from hexmind.recon.whatweb_runner import WhatWebRunner
from hexmind.recon.whois_runner import WhoisRunner

if TYPE_CHECKING:
    from rich.console import Console
    from sqlalchemy.orm import Session


class ReconOrchestrator:
    """Executes all recon tools in async tiers and persists results to DB."""

    ALL_RUNNERS: dict[str, type] = {
        "whois":    WhoisRunner,
        "dig":      DigRunner,
        "curl":     CurlRunner,
        "nmap":     NmapRunner,
        "whatweb":  WhatWebRunner,
        "sslscan":  SSLRunner,
        "nikto":    NiktoRunner,
        "gobuster": GobusterRunner,
    }

    def __init__(
        self,
        target:         str,
        profile:        str,
        db_session:     "Session",
        scan_id:        int,
        console:        "Console",
        verbose:        bool       = False,
        specific_tools: list[str]  = [],
    ) -> None:
        self.target         = target
        self.profile        = profile
        self.db_session     = db_session
        self.scan_id        = scan_id
        self.console        = console
        self.verbose        = verbose
        self.specific_tools = list(specific_tools)
        self._results:     dict[str, RunnerResult] = {}
        self._profile_cfg: dict = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])

    async def run_all(
        self, target: str, profile: str
    ) -> dict[str, RunnerResult]:
        """Execute all tools in tier order, persisting each result to DB.

        Tier 1: whois, dig, curl            — parallel
        Tier 2: nmap, whatweb, sslscan      — parallel (ssl conditional on profile)
        Tier 3: nikto, gobuster             — conditional on nmap findings

        If specific_tools is non-empty, only those tools are executed.
        Returns dict[tool_name, RunnerResult].
        """
        from hexmind.db.repository import ToolResultRepository
        from hexmind.ui.banner import print_phase_separator
        from hexmind.ui.console import print_dim, print_error, print_success

        profile_flags = {"profile": self.profile}

        async def run_and_save(
            tool_name: str,
            runner_cls: type,
            flags: dict = {},
        ) -> tuple[str, RunnerResult]:
            runner = runner_cls()
            if not runner.is_available():
                print_dim(f"  ○  {tool_name:<12} skipped  (binary not found)")
                result = RunnerResult(
                    tool_name=tool_name,
                    command_run=runner.binary,
                    raw_output="",
                    parsed_output={},
                    exit_code=-1,
                    duration_ms=0,
                    error=f"Binary '{runner.binary}' not found on PATH.",
                )
                return tool_name, result

            print_dim(f"  ⠋  {tool_name:<12} running...")
            from hexmind.constants import TOOL_TIMEOUTS
            if tool_name == "nmap":
                base_timeout = TOOL_TIMEOUTS.get("nmap", 1800)
                if self.profile == "stealth":
                    tool_timeout = 2700
                elif self.profile == "deep":
                    tool_timeout = 3600
                else:
                    tool_timeout = base_timeout
            else:
                tool_timeout = TOOL_TIMEOUTS.get(tool_name, 300)
            if tool_name == "nikto" and self.profile == "deep":
                tool_timeout = 600
            result = await runner.run(self.target, flags, timeout=tool_timeout)

            elapsed = f"{result.duration_ms / 1000:.1f}s"
            if result.success:
                summary = self._summarize(tool_name, result)
                print_success(f"{tool_name:<12} → {elapsed:<8} {summary}")
            else:
                err = (result.error or "unknown error")[:60]
                print_error(f"{tool_name:<12} → {elapsed:<8} FAILED: {err}")

            if self.db_session is not None:
                try:
                    ToolResultRepository(self.db_session).save(
                        self.scan_id, result.to_tool_result_data()
                    )
                except Exception as e:
                    print_dim(f"    DB save error for {tool_name}: {e}")

            return tool_name, result

        def should_run(name: str) -> bool:
            if self.specific_tools:
                return name in self.specific_tools
            return True

        def gather_results(raw: list) -> None:
            for r in raw:
                if isinstance(r, tuple):
                    self._results[r[0]] = r[1]

        print_phase_separator("PHASE 1 — RECON PIPELINE", "RUNNING")

        # ── Tier 1: whois, dig, curl ──────────────────────────────────────
        tier1 = [
            run_and_save(name, cls, profile_flags)
            for name, cls in [
                ("whois", WhoisRunner),
                ("dig",   DigRunner),
                ("curl",  CurlRunner),
            ]
            if should_run(name)
        ]
        gather_results(await asyncio.gather(*tier1, return_exceptions=True))

        # ── Tier 2: nmap, whatweb, sslscan ───────────────────────────────
        tier2_runners = [
            ("nmap",    NmapRunner,    profile_flags),
            ("whatweb", WhatWebRunner, profile_flags),
        ]
        if self._profile_cfg.get("run_ssl", True):
            tier2_runners.append(("sslscan", SSLRunner, profile_flags))

        tier2 = [
            run_and_save(n, cls, f)
            for n, cls, f in tier2_runners
            if should_run(n)
        ]
        gather_results(await asyncio.gather(*tier2, return_exceptions=True))

        # ── Tier 3: nikto, gobuster (conditional) ────────────────────────
        nmap_parsed = (
            self._results["nmap"].parsed_output
            if "nmap" in self._results else {}
        )

        tier3 = []
        if should_run("nikto") and self._should_run_nikto(nmap_parsed):
            nikto_flags = {
                "nikto_mode": self._profile_cfg.get("nikto_mode", "light")
            }
            tier3.append(run_and_save("nikto", NiktoRunner, nikto_flags))

        if should_run("gobuster") and self._should_run_gobuster(nmap_parsed):
            tier3.append(run_and_save("gobuster", GobusterRunner, profile_flags))

        if tier3:
            gather_results(await asyncio.gather(*tier3, return_exceptions=True))

        print_phase_separator("PHASE 1 — RECON PIPELINE", "DONE")
        return self._results

    async def run_single(
        self,
        tool_name:   str,
        custom_args: list[str] = [],
    ) -> RunnerResult:
        """Run a single named tool with optional AI-specified custom arguments.

        Used by AgenticLoop for AI-triggered follow-up scans.
        Saves result to DB and updates internal results cache.
        """
        cls = self.ALL_RUNNERS.get(tool_name)
        if cls is None:
            return RunnerResult(
                tool_name=tool_name,
                command_run="",
                raw_output="",
                parsed_output={},
                exit_code=-1,
                duration_ms=0,
                error=f"Unknown tool: {tool_name}",
            )

        runner = cls()
        flags  = {"custom_args": list(custom_args)} if custom_args else {}
        result = await runner.run(self.target, flags)

        if self.db_session is not None:
            try:
                from hexmind.db.repository import ToolResultRepository
                ToolResultRepository(self.db_session).save(
                    self.scan_id, result.to_tool_result_data()
                )
            except Exception:
                pass

        self._results[tool_name] = result
        return result

    def get_available_tools(self) -> list[str]:
        """Return names of all tools whose binaries are present on PATH."""
        return [
            name for name, cls in self.ALL_RUNNERS.items()
            if cls().is_available()
        ]

    def _should_run_nikto(self, nmap_parsed: dict) -> bool:
        """
        Run nikto if:
        1. Profile has nikto enabled (nikto_mode is not None)
        2. AND either:
           a. nmap found a web port (80/443/8080/8443/8000), OR
           b. curl successfully got HTTP 200 (nmap may have timed out)
        """
        if self._profile_cfg.get("nikto_mode") is None:
            return False

        web_ports  = {80, 443, 8080, 8443, 8000}
        open_ports = set(nmap_parsed.get("open_ports", []))
        nmap_found = bool(open_ports & web_ports) or nmap_parsed.get("has_web", False)

        # Fallback: check if curl found HTTP even when nmap timed out
        curl_found  = False
        curl_result = self._results.get("curl")
        if curl_result and curl_result.parsed_output:
            status     = curl_result.parsed_output.get("status_code", 0)
            curl_found = isinstance(status, int) and 200 <= status < 500

        return nmap_found or curl_found

    def _should_run_gobuster(self, nmap_parsed: dict) -> bool:
        """Return True if profile enables gobuster and web ports were found."""
        if not self._profile_cfg.get("run_gobuster", False):
            return False
        return self._should_run_nikto(nmap_parsed)

    def _summarize(self, tool_name: str, result: RunnerResult) -> str:
        """Return a short one-line summary of key findings for console output."""
        p = result.parsed_output
        if tool_name == "nmap":
            ports = p.get("open_ports", [])
            return f"{len(ports)} open ports: {ports[:5]}"
        if tool_name == "whois":
            r = p.get("registrar") or "unknown"
            return f"registrar: {r}"
        if tool_name == "dig":
            a       = p.get("a_records", [])
            missing = p.get("missing_email_security", [])
            s = f"A: {', '.join(a[:3])}"
            if missing:
                s += f"  missing: {', '.join(missing)}"
            return s
        if tool_name == "curl":
            code    = p.get("status_code", "?")
            missing = len(p.get("missing_security_headers", []))
            srv     = p.get("server", "")
            return f"HTTP {code}  server: {srv}  missing {missing} sec headers"
        if tool_name == "whatweb":
            return f"{p.get('plugin_count', 0)} plugins  cms={p.get('cms')}"
        if tool_name == "sslscan":
            return f"grade={p.get('grade', '?')}  issues={len(p.get('issues', []))}"
        if tool_name == "nikto":
            return f"{p.get('total_findings', 0)} findings"
        if tool_name == "gobuster":
            return (
                f"{p.get('total_found', 0)} paths  "
                f"interesting={len(p.get('interesting', []))}"
            )
        return ""
