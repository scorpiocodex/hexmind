"""Scan session orchestrator: coordinates recon, AI, and database phases."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from hexmind.config          import get_config
from hexmind.constants       import HEXMIND_DIR, SCAN_PROFILES
from hexmind.core.exceptions import ValidationError, OllamaNotRunningError
from hexmind.core.target_validator import TargetValidator
from hexmind.core.agentic_loop     import AgenticLoop, AgenticLoopState
from hexmind.db.database           import DatabaseManager
from hexmind.db.repository         import (
    TargetRepository, ScanRepository, ToolResultRepository,
    FindingRepository, AIConversationRepository,
)
from hexmind.recon.orchestrator import ReconOrchestrator
from hexmind.ui.console         import (
    console, print_error, print_warning, print_dim
)
from hexmind.ui.banner  import print_phase_separator
from hexmind.ui.panels  import render_findings_table, render_scan_complete_box


@dataclass
class ScanSessionResult:
    """Immutable result returned after a scan session completes."""

    scan_id:           int
    target:            str
    findings:          list
    risk_score:        Optional[int]
    executive_summary: Optional[str]
    tool_results:      dict
    duration_seconds:  float


class ScanSession:
    """Top-level coordinator for a single HexMind scan. Called by the CLI scan command."""

    def __init__(
        self,
        target:         str,
        profile:        str       = "standard",
        verbose:        bool      = False,
        no_ai:          bool      = False,
        allow_private:  bool      = False,
        specific_tools: list[str] = [],
    ) -> None:
        self.target         = target
        self.profile        = profile
        self.verbose        = verbose
        self.no_ai          = no_ai
        self.allow_private  = allow_private
        self.specific_tools = list(specific_tools)
        self.cfg            = get_config()
        self._start_time    = time.monotonic()

    async def run(self) -> ScanSessionResult:
        """
        Full scan pipeline:
          1. Validate target
          2. Init DB + create scan record
          3. Run recon phase
          4. Run AI agentic loop (unless --no-ai)
          5. Finalize and display results
        """
        # ── 1. Validate target ────────────────────────────────────────────
        validator = TargetValidator()
        try:
            _, normalized, target_type = validator.validate(
                self.target, allow_private=self.allow_private
            )
        except ValidationError as e:
            print_error(str(e))
            raise

        self.target = normalized

        # ── 2. Init DB ────────────────────────────────────────────────────
        HEXMIND_DIR.mkdir(parents=True, exist_ok=True)
        self.cfg.reports_dir.mkdir(parents=True, exist_ok=True)

        dm = DatabaseManager(self.cfg.db_path)
        dm.init()

        try:
            with dm.get_db() as db:
                t_repo  = TargetRepository(db)
                s_repo  = ScanRepository(db)
                tr_repo = ToolResultRepository(db)
                f_repo  = FindingRepository(db)
                ai_repo = AIConversationRepository(db)

                target_record = t_repo.get_or_create(self.target, target_type)
                scan_record   = s_repo.create(
                    target_id=target_record.id,
                    profile=self.profile,
                    tool_flags={},
                )
                scan_id = scan_record.id
                s_repo.update_status(scan_id, "running")

                repos = {
                    "target":  t_repo,
                    "scan":    s_repo,
                    "tool":    tr_repo,
                    "finding": f_repo,
                    "ai":      ai_repo,
                }

                console.print(
                    f"  Scan ID › [cyan]#{scan_id:04d}[/]  "
                    f"DB › [dim]{self.cfg.db_path}[/]"
                )

                # ── 3. Recon phase ────────────────────────────────────────
                tool_results = await self._run_recon_phase(db, scan_id, repos)

                # ── 3b. Direct tool→findings bridge ──────────────────────
                bridge_findings = self._run_tool_bridge(
                    tool_results, target_record.value, scan_id, repos
                )

                # ── 4. AI phase ───────────────────────────────────────────
                state = AgenticLoopState(
                    all_tool_results = tool_results,
                    all_findings     = bridge_findings,
                )
                if not self.no_ai:
                    state = await self._run_ai_phase(
                        scan_id, tool_results, repos, db, bridge_findings
                    )

                # ── 5. Finalize ───────────────────────────────────────────
                self._finalize_scan(scan_id, state, repos, state.all_findings)

                duration = time.monotonic() - self._start_time

                return ScanSessionResult(
                    scan_id           = scan_id,
                    target            = self.target,
                    findings          = state.all_findings,
                    risk_score        = state.risk_score,
                    executive_summary = state.executive_summary,
                    tool_results      = tool_results,
                    duration_seconds  = duration,
                )
        except Exception as exc:
            # Attempt to mark scan failed; best-effort — original exception re-raised
            try:
                with dm.get_db() as db2:
                    ScanRepository(db2).fail(
                        scan_record.id if 'scan_record' in dir() else 0,
                        str(exc),
                    )
            except Exception:
                pass
            raise
        finally:
            dm.close()

    async def _run_recon_phase(self, db, scan_id: int, repos: dict) -> dict:
        """Phase 1: Run all recon tools via orchestrator."""
        orchestrator = ReconOrchestrator(
            target         = self.target,
            profile        = self.profile,
            db_session     = db,
            scan_id        = scan_id,
            console        = console,
            verbose        = self.verbose,
            specific_tools = self.specific_tools,
        )
        return await orchestrator.run_all(self.target, self.profile)

    def _run_tool_bridge(
        self,
        tool_results: dict,
        target:       str,
        scan_id:      int,
        repos:        dict,
    ) -> list:
        """Convert deterministic tool output directly to findings (no AI)."""
        from hexmind.core.tool_findings_bridge import (
            nikto_to_findings, dig_to_findings, curl_to_findings,
        )

        all_bridge: list = []
        f_repo = repos["finding"]

        nikto_result = tool_results.get("nikto")
        if nikto_result and nikto_result.parsed_output:
            nf = nikto_to_findings(nikto_result.parsed_output, target)
            if nf:
                f_repo.save_batch(scan_id, nf)
                all_bridge.extend(nf)
                print_dim(f"  Bridge: {len(nf)} nikto findings converted directly")

        dig_result = tool_results.get("dig")
        if dig_result and dig_result.parsed_output:
            df = dig_to_findings(dig_result.parsed_output, target)
            if df:
                f_repo.save_batch(scan_id, df)
                all_bridge.extend(df)
                print_dim(f"  Bridge: {len(df)} DNS security findings converted directly")

        curl_result = tool_results.get("curl")
        if curl_result and curl_result.parsed_output:
            cf = curl_to_findings(curl_result.parsed_output, target)
            if cf:
                f_repo.save_batch(scan_id, cf)
                all_bridge.extend(cf)
                print_dim(f"  Bridge: {len(cf)} HTTP header findings converted directly")

        return all_bridge

    async def _run_ai_phase(
        self,
        scan_id:         int,
        tool_results:    dict,
        repos:           dict,
        db_session,
        bridge_findings: list = [],
    ) -> AgenticLoopState:
        """Phases 2–4: Agentic AI analysis loop."""
        from hexmind.ai.engine         import OllamaEngine
        from hexmind.search.duckduckgo import DuckDuckGoSearch
        from hexmind.search.cve_lookup import CVELookup

        engine = OllamaEngine(self.cfg.ai.base_url, self.cfg.ai.model)
        try:
            await engine.check_available()

            orch = ReconOrchestrator(
                target     = self.target,
                profile    = self.profile,
                db_session = db_session,
                scan_id    = scan_id,
                console    = console,
                verbose    = self.verbose,
            )

            loop = AgenticLoop(
                scan_id        = scan_id,
                target         = self.target,
                profile        = self.profile,
                engine         = engine,
                orchestrator   = orch,
                searcher       = DuckDuckGoSearch(
                    rate_limit=self.cfg.search.ddg_rate_limit
                ),
                cve_lookup     = CVELookup(),
                repos          = repos,
                console_obj    = console,
                max_iterations = SCAN_PROFILES[self.profile].get(
                    "ai_passes", self.cfg.scan.max_iterations
                ),
            )

            return await loop.execute(tool_results, initial_findings=bridge_findings)

        except OllamaNotRunningError as e:
            print_error(str(e))
            print_warning(
                "Skipping AI analysis. "
                "Re-run without --no-ai when Ollama is running."
            )
            return AgenticLoopState(all_tool_results=tool_results)
        except Exception as e:
            print_error(f"AI phase error: {e}")
            return AgenticLoopState(all_tool_results=tool_results)
        finally:
            await engine.close()

    def _finalize_scan(
        self,
        scan_id:        int,
        state:          AgenticLoopState,
        repos:          dict,
        final_findings: list = [],
    ) -> None:
        """Mark scan complete, print findings table and summary box."""
        s_repo: ScanRepository    = repos["scan"]
        f_repo: FindingRepository = repos["finding"]

        findings = f_repo.get_for_scan(scan_id)

        # Calculate risk from the final deduplicated FindingData list,
        # not the DB query which may include pre-dedup bridge findings.
        from hexmind.constants import RISK_WEIGHTS
        if state.risk_score is not None:
            effective_risk = state.risk_score
        elif final_findings:
            score = sum(
                RISK_WEIGHTS.get(f.severity.lower(), 0)
                for f in final_findings
                if not getattr(f, "false_positive", False)
            )
            effective_risk = min(100, score)
        else:
            effective_risk = 0

        s_repo.finish(
            scan_id,
            risk_score        = effective_risk,
            executive_summary = state.executive_summary,
        )
        counts   = f_repo.count_by_severity(scan_id)

        # Print findings table
        if findings:
            print_phase_separator("FINDINGS", "DONE")
            table = render_findings_table(
                [f.to_finding_data() for f in findings]
            )
            console.print(table)

        # Print executive summary if available
        if state.executive_summary:
            from rich.panel import Panel
            console.print()
            console.print(
                Panel(
                    state.executive_summary,
                    title="[bold]Executive Summary[/]",
                    border_style="steel_blue",
                    padding=(1, 2),
                )
            )

        # Print final summary box
        duration = time.monotonic() - self._start_time
        m, s     = divmod(int(duration), 60)
        dur_str  = f"{m}m {s}s" if m else f"{s}s"

        console.print()
        console.print(render_scan_complete_box(
            scan_id    = scan_id,
            duration   = dur_str,
            findings   = counts,
            risk_score = effective_risk,
        ))
