"""Context builder: assembles tool results and history into AI message lists."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hexmind.ai.prompts import (
    ANALYSIS_PROMPT_TEMPLATE,
    MAX_CONTEXT_TOKENS,
    MAX_TOOL_CHARS,
    SYSTEM_PROMPT,
    _final_instruction,
    _iteration_instruction,
    format_tool_result,
)

if TYPE_CHECKING:
    from hexmind.ai.engine import AIEngine

# Tool priority for context window truncation.
# Higher priority tools keep their full output; lower-priority tools
# are trimmed first when the context budget is tight.
TOOL_PRIORITY: list[str] = [
    "nmap",      # 1 — most information-dense
    "nikto",     # 2 — direct vulnerability findings
    "sslscan",   # 3 — crypto issues
    "whatweb",   # 4 — technology stack
    "curl",      # 5 — headers
    "gobuster",  # 6 — discovered paths
    "dig",       # 7 — DNS (lightweight)
    "whois",     # 8 — registration info (lowest priority)
]


class ContextBuilder:
    """Formats tool outputs and conversation history into Ollama message payloads."""

    def __init__(
        self,
        target:  str,
        profile: str,
        engine:  "AIEngine",
    ) -> None:
        self.target  = target
        self.profile = profile
        self.engine  = engine

    def build_initial_context(
        self,
        tool_results:     dict,
        iteration:        int,
        max_iterations:   int,
        previous_summary: str = "",
        search_results:   str = "",
    ) -> list[dict]:
        """Build the initial Ollama messages list from baseline recon tool results.

        Returns:
          [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": <filled analysis prompt>},
          ]
        """
        tool_text = self._format_all_tools(tool_results, max_iterations)

        prev_section = ""
        if previous_summary:
            prev_section = (
                "━━━━ PREVIOUS FINDINGS SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                + previous_summary
                + "\n\n"
            )

        search_section = ""
        if search_results:
            search_section = (
                "━━━━ SEARCH & CVE RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                + search_results
                + "\n\n"
            )

        user_content = ANALYSIS_PROMPT_TEMPLATE.format(
            target=self.target,
            profile=self.profile,
            iteration=iteration,
            max_iterations=max_iterations,
            tool_results_text=tool_text,
            previous_section=prev_section,
            search_section=search_section,
            iteration_instruction=_iteration_instruction(iteration, max_iterations),
            final_instruction=_final_instruction(iteration, max_iterations),
        )

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_content},
        ]

    def build_followup_context(
        self,
        messages:         list[dict],
        assistant_reply:  str,
        new_tool_results: dict,
        search_results:   list[str],
        iteration:        int,
        max_iterations:   int,
    ) -> list[dict]:
        """Extend the conversation with the AI's previous reply and new tool results.

        Returns a new messages list (does not mutate input).
        """
        new_tool_text = self._format_all_tools(new_tool_results, max_iterations)
        search_text   = "\n".join(search_results) if search_results else ""

        followup = (
            f"FOLLOW-UP DATA (Pass {iteration} of {max_iterations})\n\n"
            "━━━━ NEW TOOL RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            + new_tool_text
        )
        if search_text:
            followup += (
                "\n━━━━ SEARCH RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                + search_text
                + "\n\n"
            )
        followup += (
            "\nContinue your analysis. Emit additional <finding> blocks "
            "for any new vulnerabilities found in this data. "
            + _iteration_instruction(iteration, max_iterations)
        )

        return messages + [
            {"role": "assistant", "content": assistant_reply},
            {"role": "user",      "content": followup},
        ]

    def summarize_previous_findings(self, findings: list) -> str:
        """Return a compact text summary of prior findings for context injection."""
        if not findings:
            return "No findings recorded yet."
        lines: list[str] = []
        for f in sorted(findings, key=lambda x: x.severity_rank()):
            cves = f", {', '.join(f.cve_ids)}" if f.cve_ids else ""
            conf = int(f.confidence_score * 100)
            lines.append(
                f"  [{f.severity.upper()}] {f.title}"
                f" ({f.affected_component or 'N/A'})"
                f"{cves} — {conf}% confidence"
            )
        return "\n".join(lines)

    def _format_all_tools(
        self,
        tool_results:   dict,
        max_iterations: int,
    ) -> str:
        """Format all tool results into a single text block.

        Manages context budget:
          1. Order tools by TOOL_PRIORITY
          2. Estimate total token cost via engine.estimate_tokens()
          3. If over budget, reduce char limits for lowest-priority tools
        """
        sections: list[tuple[int, str, str]] = []

        for name in TOOL_PRIORITY:
            result = tool_results.get(name)
            if result is None:
                continue
            parsed = (
                result.parsed_output
                if hasattr(result, "parsed_output")
                else result
            )
            body   = format_tool_result(name, parsed)
            header = f"=== {name.upper()} ===\n"
            sections.append((TOOL_PRIORITY.index(name), name, header + body))

        # Append any tools not in TOOL_PRIORITY
        for name, result in tool_results.items():
            if name not in TOOL_PRIORITY:
                parsed = (
                    result.parsed_output
                    if hasattr(result, "parsed_output")
                    else result
                )
                body = format_tool_result(name, parsed)
                sections.append((99, name, f"=== {name.upper()} ===\n" + body))

        combined = "\n\n".join(s[2] for s in sections)

        # Progressively truncate low-priority tools if over token budget
        if self.engine.estimate_tokens(combined) > MAX_CONTEXT_TOKENS:
            budget_per_tool = MAX_CONTEXT_TOKENS * 4 // max(len(sections), 1)
            trimmed: list[str] = []
            for priority, name, block in sections:
                if priority >= 5:
                    max_c  = min(MAX_TOOL_CHARS, budget_per_tool)
                    lines  = block.splitlines()
                    block  = "\n".join(lines[: max_c // 80])
                trimmed.append(block)
            combined = "\n\n".join(trimmed)

        return combined
