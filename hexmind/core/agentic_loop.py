"""Agentic loop controller: multi-pass AI ↔ tool feedback orchestration."""

from __future__ import annotations

import asyncio
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from hexmind.ai.parser          import AIParser, ParsedAIResponse, ToolRequest, SearchRequest, CVELookupRequest
from hexmind.ai.context_builder import ContextBuilder
from hexmind.db.schemas         import FindingData
from hexmind.db.repository      import FindingRepository, AIConversationRepository
from hexmind.constants          import TOOL_BINARIES, COLOR_CYAN, COLOR_PURPLE
from hexmind.ui.console         import console, print_ai, print_dim, print_warning

if TYPE_CHECKING:
    from hexmind.ai.engine          import OllamaEngine
    from hexmind.recon.orchestrator import ReconOrchestrator
    from hexmind.search.duckduckgo  import DuckDuckGoSearch
    from hexmind.search.cve_lookup  import CVELookup


@dataclass
class AgenticLoopState:
    """Full mutable state carried across all loop iterations."""

    iteration:              int               = 0
    all_tool_results:       dict              = field(default_factory=dict)
    all_findings:           list[FindingData] = field(default_factory=list)
    ai_conversation:        list[dict]        = field(default_factory=list)
    executed_tool_requests: set               = field(default_factory=set)
    search_results_text:    str               = ""
    converged:              bool              = False
    risk_score:             Optional[int]     = None
    executive_summary:      Optional[str]     = None
    last_finding_titles:    set[str]          = field(default_factory=set)


class AgenticLoop:
    """
    Multi-pass AI vulnerability analysis loop.

    Each iteration:
      1. Build context from all tool results
      2. Stream AI response to terminal
      3. Parse response for findings, tool requests, searches
      4. Execute requested tools and searches
      5. Check convergence
      6. Repeat until converged or max_iterations reached
    """

    def __init__(
        self,
        scan_id:        int,
        target:         str,
        profile:        str,
        engine:         "OllamaEngine",
        orchestrator:   "ReconOrchestrator",
        searcher:       "DuckDuckGoSearch",
        cve_lookup:     "CVELookup",
        repos:          dict,
        console_obj,
        max_iterations: int = 5,
    ) -> None:
        self.scan_id        = scan_id
        self.target         = target
        self.profile        = profile
        self.engine         = engine
        self.orchestrator   = orchestrator
        self.searcher       = searcher
        self.cve_lookup     = cve_lookup
        self.repos          = repos
        self.console        = console_obj
        self.max_iterations = max_iterations
        self.parser         = AIParser()
        self.ctx_builder    = ContextBuilder(target, profile, engine)

    async def execute(self, initial_tool_results: dict) -> AgenticLoopState:
        """Main entry point. Runs the full agentic loop. Returns final AgenticLoopState."""
        state = AgenticLoopState(all_tool_results=dict(initial_tool_results))

        for iteration in range(1, self.max_iterations + 1):
            state.iteration = iteration
            state = await self.run_iteration(iteration, state)

            if state.converged:
                print_dim(f"  Converged after {iteration} pass(es).")
                break

        return state

    async def run_iteration(
        self,
        iteration: int,
        state:     AgenticLoopState,
    ) -> AgenticLoopState:
        """Execute one complete loop iteration."""
        from hexmind.ui.banner import print_phase_separator

        is_final = iteration >= self.max_iterations
        print_phase_separator(
            f"PHASE 2 — AI ANALYSIS  Pass {iteration}/{self.max_iterations}",
            "RUNNING",
        )

        # ── 1. Build context ─────────────────────────────────────────────────
        if iteration == 1:
            messages = self.ctx_builder.build_initial_context(
                tool_results=state.all_tool_results,
                iteration=iteration,
                max_iterations=self.max_iterations,
                previous_summary="",
                search_results=state.search_results_text,
            )
        else:
            prev_summary = self.ctx_builder.summarize_previous_findings(
                state.all_findings
            )
            messages = self.ctx_builder.build_initial_context(
                tool_results=state.all_tool_results,
                iteration=iteration,
                max_iterations=self.max_iterations,
                previous_summary=prev_summary,
                search_results=state.search_results_text,
            )

        # ── 2. Stream AI response ─────────────────────────────────────────────
        token_est = self.engine.estimate_tokens(messages[-1]["content"])
        print_ai(
            f"Feeding ~{token_est:,} tokens to "
            f"[bold]{self.engine.model}[/] ..."
        )
        console.print()

        ai_response = await self._stream_ai_response(messages)

        # Save to DB
        ai_repo: AIConversationRepository = self.repos.get("ai")
        if ai_repo:
            token_count = self.engine.estimate_tokens(ai_response)
            ai_repo.save_message(
                scan_id=self.scan_id,
                role="assistant",
                content=ai_response,
                iteration=iteration,
                token_count=token_count,
            )

        # ── 3. Parse response ─────────────────────────────────────────────────
        parsed: ParsedAIResponse = self.parser.parse_structured(
            ai_response, target=self.target
        )

        # ── 4. Save new findings ──────────────────────────────────────────────
        new_findings = self._merge_findings(state.all_findings, parsed.findings)
        added_count  = len(new_findings) - len(state.all_findings)
        state.all_findings = new_findings

        f_repo: FindingRepository = self.repos.get("finding")
        if f_repo and parsed.findings:
            f_repo.save_batch(self.scan_id, parsed.findings)

        if parsed.risk_score is not None:
            state.risk_score = parsed.risk_score
        if parsed.executive_summary:
            state.executive_summary = parsed.executive_summary

        console.print()
        print_dim(
            f"  Pass {iteration} complete — "
            f"{len(parsed.findings)} findings parsed, "
            f"{added_count} new"
        )

        # ── 5. Check convergence ──────────────────────────────────────────────
        deduped_tool_reqs = self.parser.deduplicate_tool_requests(
            parsed.tool_requests, state.executed_tool_requests
        )

        if self._check_convergence(state, parsed.findings, deduped_tool_reqs, is_final):
            state.converged = True
            print_phase_separator(
                f"PHASE 2 — AI ANALYSIS  Pass {iteration}/{self.max_iterations}",
                "DONE",
            )
            return state

        # ── 6. Execute tool requests ──────────────────────────────────────────
        if deduped_tool_reqs and not is_final:
            new_results = await self._execute_tool_requests(deduped_tool_reqs, state)
            state.all_tool_results.update(new_results)

        # ── 7. Execute searches ───────────────────────────────────────────────
        if (parsed.search_requests or parsed.cve_lookups) and not is_final:
            new_search_text = await self._execute_searches(
                parsed.search_requests, parsed.cve_lookups
            )
            if new_search_text:
                state.search_results_text = (
                    state.search_results_text + "\n\n" + new_search_text
                ).strip()

        state.last_finding_titles = {f.title for f in state.all_findings}
        print_phase_separator(
            f"PHASE 2 — AI ANALYSIS  Pass {iteration}/{self.max_iterations}",
            "DONE",
        )
        return state

    def _render_finding_card(self, finding: "FindingData", n: int) -> None:
        """Print a formatted finding card to the console."""
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        from hexmind.constants import (
            SEVERITY_COLORS, COLOR_WHITE, COLOR_SLATE,
            COLOR_GREEN, COLOR_RED, COLOR_ORANGE,
        )

        sev   = finding.severity.lower()
        color = SEVERITY_COLORS.get(sev, COLOR_SLATE)
        cves  = ", ".join(finding.cve_ids) if finding.cve_ids else "—"
        conf  = f"{int(finding.confidence_score * 100)}%"

        rows = [
            ("Severity",    f"[bold {color}]● {finding.severity.upper()}[/]"),
            ("Category",    finding.category or "—"),
            ("Title",       f"[bold {COLOR_WHITE}]{finding.title}[/]"),
            ("Description", finding.description[:200] + (
                "..." if len(finding.description) > 200 else ""
            )),
            ("Component",   finding.affected_component or "—"),
            ("CVEs",        f"[cyan]{cves}[/]" if cves != "—" else "—"),
            ("Exploit",     (finding.exploit_notes or "—")[:150]),
            ("Remediation", (finding.remediation or "—")[:150]),
            ("Confidence",  f"[bold {color}]{conf}[/]"),
        ]

        table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
        table.add_column("field", style=f"dim {COLOR_SLATE}", width=14, justify="right")
        table.add_column("value", overflow="fold")

        for field, value in rows:
            table.add_row(field, value)

        border_colors = {
            "critical": COLOR_RED,
            "high":     COLOR_ORANGE,
            "medium":   "yellow",
            "low":      COLOR_GREEN,
            "info":     COLOR_SLATE,
        }
        border = border_colors.get(sev, COLOR_SLATE)

        console.print(Panel(
            table,
            title=f"[bold {color}] Finding {n} [/]",
            title_align="left",
            border_style=border,
            padding=(0, 1),
        ))

    async def _stream_ai_response(self, messages: list[dict]) -> str:
        """Stream AI response, rendering findings as formatted cards. Returns full raw string."""
        full_buffer:   list[str] = []
        xml_buffer:    list[str] = []
        finding_count  = 0
        in_finding     = False
        in_tool_req    = False
        in_search_req  = False
        in_cve_lookup  = False
        suppress_raw   = False

        console.print(
            f"[{COLOR_PURPLE}]┌─ AI Analysis Stream "
            f"──────────────────────────────────────[/]"
        )
        console.print()

        try:
            async for chunk in self.engine.generate_stream(messages):
                full_buffer.append(chunk)

                for char in chunk:
                    xml_buffer.append(char)
                    current = "".join(xml_buffer)

                    # ── Detect opening tags ────────────────────────────────
                    if "<finding>" in current and not in_finding:
                        in_finding   = True
                        suppress_raw = True
                        xml_buffer   = list(current[current.index("<finding>"):])
                        continue

                    if "<tool_request>" in current and not in_tool_req:
                        in_tool_req  = True
                        suppress_raw = True
                        xml_buffer   = list(current[current.index("<tool_request>"):])
                        continue

                    if "<search_request>" in current and not in_search_req:
                        in_search_req = True
                        suppress_raw  = True
                        xml_buffer    = list(current[current.index("<search_request>"):])
                        continue

                    if "<cve_lookup>" in current and not in_cve_lookup:
                        in_cve_lookup = True
                        suppress_raw  = True
                        xml_buffer    = list(current[current.index("<cve_lookup>"):])
                        continue

                    # ── Detect closing tags ────────────────────────────────
                    if in_finding and "</finding>" in current:
                        block = "".join(xml_buffer)
                        finding_data = self.parser._parse_finding(
                            block.replace("<finding>", "").replace("</finding>", "")
                        )
                        if finding_data:
                            finding_count += 1
                            console.print()
                            self._render_finding_card(finding_data, finding_count)
                        in_finding   = False
                        suppress_raw = False
                        xml_buffer   = []
                        continue

                    if in_tool_req and "</tool_request>" in current:
                        block  = "".join(xml_buffer)
                        tool   = self.parser._get_text(block, "tool").lower().strip()
                        args   = self.parser._get_text(block, "args").strip()
                        args   = args.replace("{target}", self.target)
                        reason = self.parser._get_text(block, "reason").strip()
                        if tool:
                            console.print(
                                f"  [{COLOR_PURPLE}]⚡ AI requests:[/] "
                                f"[bold]{tool}[/] [dim]{args[:50]}[/]"
                            )
                            if reason:
                                console.print(f"  [dim]  Reason: {reason[:80]}[/]")
                        in_tool_req  = False
                        suppress_raw = False
                        xml_buffer   = []
                        continue

                    if in_search_req and "</search_request>" in current:
                        block = "".join(xml_buffer)
                        query = self.parser._get_text(block, "query")
                        if query:
                            console.print(
                                f"  [{COLOR_CYAN}]🔍 AI searches:[/] "
                                f"[dim]{query[:80]}[/]"
                            )
                        in_search_req = False
                        suppress_raw  = False
                        xml_buffer    = []
                        continue

                    if in_cve_lookup and "</cve_lookup>" in current:
                        block  = "".join(xml_buffer)
                        cve_id = self.parser._get_text(block, "cve_id")
                        if cve_id:
                            console.print(
                                f"  [{COLOR_CYAN}]🔍 CVE lookup:[/] "
                                f"[dim]{cve_id}[/]"
                            )
                        in_cve_lookup = False
                        suppress_raw  = False
                        xml_buffer    = []
                        continue

                    # ── Print plain text outside XML blocks ────────────────
                    if not suppress_raw:
                        current_buf = "".join(xml_buffer)
                        if not current_buf.startswith("<"):
                            # Regular text — print immediately
                            console.print(char, end="", highlight=False)
                            xml_buffer = []
                        elif len(current_buf) > 20:
                            # Too long for any of our tags — flush as-is
                            console.print(current_buf, end="", highlight=False)
                            xml_buffer = []
                        # else: might still be forming a tag — keep accumulating

        except Exception as e:
            console.print(f"\n[bold red]Stream error: {e}[/]")

        console.print()
        console.print(
            f"[{COLOR_PURPLE}]└──────────────────────────────────────"
            f"────────────────────────────[/]"
        )
        console.print()

        return "".join(full_buffer)

    async def _execute_tool_requests(
        self,
        requests: list[ToolRequest],
        state:    AgenticLoopState,
    ) -> dict:
        """Execute AI-requested tool runs. Validates names, parses args with shlex."""
        new_results: dict = {}

        for req in requests:
            tool_name = req.tool.lower().strip()

            if tool_name not in TOOL_BINARIES:
                print_warning(f"AI requested unknown tool '{tool_name}' — skipped.")
                continue

            print_ai(
                f"Agentic tool request: [bold]{tool_name}[/] "
                f"[dim]{req.args[:60]}[/]"
            )
            if req.reason:
                print_dim(f"  Reason: {req.reason}")

            try:
                custom_args = shlex.split(req.args)
                custom_args = [a for a in custom_args if a != self.target]
            except ValueError:
                custom_args = req.args.split()

            key = (tool_name, req.args)
            state.executed_tool_requests.add(key)

            try:
                result = await self.orchestrator.run_single(tool_name, custom_args)
                new_results[f"{tool_name}_agentic_{state.iteration}"] = result
                print_dim(f"  → {tool_name} completed ({result.duration_ms}ms)")
            except Exception as e:
                print_warning(f"  → {tool_name} failed: {e}")

        return new_results

    async def _execute_searches(
        self,
        search_reqs: list[SearchRequest],
        cve_reqs:    list[CVELookupRequest],
    ) -> str:
        """Run DDG searches and CVE lookups. Returns formatted text for context."""
        parts: list[str] = []

        for req in search_reqs[:3]:
            try:
                print_ai(f"Searching: {req.query[:60]}")
                results = await self.searcher.search(req.query, max_results=3)
                if results:
                    formatted = self.searcher.format_for_prompt(results)
                    parts.append(f"[Search: {req.query}]\n{formatted}")
            except Exception as e:
                print_dim(f"  Search failed: {e}")

        for req in cve_reqs[:5]:
            try:
                print_ai(f"CVE lookup: {req.cve_id}")
                detail = await self.cve_lookup.lookup(req.cve_id)
                if detail:
                    formatted = self.cve_lookup.format_for_prompt(detail)
                    parts.append(f"[CVE: {req.cve_id}]\n{formatted}")
            except Exception as e:
                print_dim(f"  CVE lookup failed: {e}")

        return "\n\n".join(parts)

    def _check_convergence(
        self,
        state:        AgenticLoopState,
        new_findings: list[FindingData],
        tool_reqs:    list[ToolRequest],
        is_final:     bool,
    ) -> bool:
        """
        Converge if:
        1. is_final (last iteration)
        2. No new tool requests AND no new finding titles vs previous iteration
        """
        if is_final:
            return True

        if not tool_reqs:
            new_titles = {f.title for f in new_findings}
            if state.last_finding_titles and not (new_titles - state.last_finding_titles):
                return True

        return False

    def _normalize_component(self, component: str) -> str:
        """Normalize component strings for dedup comparison."""
        c = (component or "").lower()
        c = c.replace("httpd/", "/")
        c = c.replace("httpd ", " ")
        c = c.replace(" ", "")
        return c

    def _normalize_title(self, title: str) -> str:
        """Normalize finding title for dedup comparison."""
        import re
        t = title.strip().strip('"').strip("'").lower()
        t = re.sub(r"\s*\([^)]*\)", "", t).strip()
        t = re.sub(r"apache\s+\d+[\.\d]+\s*", "apache ", t)
        t = re.sub(r"apache\s+http\s+server\s*", "apache ", t)
        t = re.sub(r"apache\s+httpd\s*", "apache ", t)
        t = re.sub(r"\s+", " ", t).strip()
        return t

    def _merge_findings(
        self,
        existing: list[FindingData],
        new:      list[FindingData],
    ) -> list[FindingData]:
        """Merge findings with two-stage deduplication: exact key + fuzzy title."""
        import difflib

        index: dict[tuple[str, str], FindingData] = {
            (
                self._normalize_title(f.title),
                self._normalize_component(f.affected_component or ""),
            ): f
            for f in existing
        }

        for f in new:
            key = (
                self._normalize_title(f.title),
                self._normalize_component(f.affected_component or ""),
            )

            if key in index:
                if f.confidence_score > index[key].confidence_score:
                    index[key] = f
                continue

            new_norm_title     = self._normalize_title(f.title)
            new_norm_component = self._normalize_component(f.affected_component or "")

            fuzzy_match = None
            best_ratio  = 0.82

            for (ex_title, ex_comp), existing_f in index.items():
                if ex_comp != new_norm_component and ex_comp and new_norm_component:
                    continue
                ratio = difflib.SequenceMatcher(None, new_norm_title, ex_title).ratio()
                if ratio > best_ratio:
                    best_ratio  = ratio
                    fuzzy_match = (ex_title, ex_comp)

            if fuzzy_match:
                if f.confidence_score > index[fuzzy_match].confidence_score:
                    index[fuzzy_match] = f
            else:
                index[key] = f

        return sorted(index.values(), key=lambda f: f.severity_rank())
