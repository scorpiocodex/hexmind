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

                # ── 4. AI phase ───────────────────────────────────────────
                state = AgenticLoopState(all_tool_results=tool_results)
                if not self.no_ai:
                    state = await self._run_ai_phase(scan_id, tool_results, repos, db)

                # ── 5. Finalize ───────────────────────────────────────────
                self._finalize_scan(scan_id, state, repos)

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

    async def _run_ai_phase(
        self,
        scan_id:      int,
        tool_results: dict,
        repos:        dict,
        db_session,
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

            return await loop.execute(tool_results)

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
        scan_id: int,
        state:   AgenticLoopState,
        repos:   dict,
    ) -> None:
        """Mark scan complete, print findings table and summary box."""
        s_repo: ScanRepository    = repos["scan"]
        f_repo: FindingRepository = repos["finding"]

        findings = f_repo.get_for_scan(scan_id)

        # Calculate fallback risk score if AI didn't produce one
        calculated_risk = None
        if state.risk_score is None and findings:
            weights = {"critical": 40, "high": 20,
                       "medium": 8, "low": 2, "info": 0}
            score = sum(
                weights.get(f.severity.lower(), 0)
                for f in findings
                if not f.false_positive
            )
            calculated_risk = min(100, score)

        effective_risk = state.risk_score or calculated_risk

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
            risk_score = state.risk_score,
        ))
