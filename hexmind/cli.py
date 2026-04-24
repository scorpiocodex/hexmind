"""Typer CLI entry point exposing all HexMind commands."""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table

from hexmind.config import get_config, reset_config_cache
from hexmind.constants import (
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_ORANGE,
    COLOR_RED,
    COLOR_SLATE,
    COLOR_SOFT_GREEN,
    COLOR_WHITE,
    COLOR_YELLOW,
    DB_PATH,
    HEXMIND_CODENAME,
    HEXMIND_DIR,
    HEXMIND_VERSION,
    SCAN_PROFILES,
    SEVERITY_COLORS,
    TOOL_BINARIES,
    VERSION_ROADMAP,
    WORDLIST_PATH,
)
from hexmind.core.exceptions import HexMindError, ValidationError
from hexmind.core.target_validator import TargetValidator
from hexmind.db.database import DatabaseManager
from hexmind.db.repository import (
    AIConversationRepository,
    FindingRepository,
    ScanRepository,
    TargetRepository,
    ToolResultRepository,
)
from hexmind.ui.banner import print_banner, print_phase_separator
from hexmind.ui.console import (
    console,
    print_dim,
    print_error,
    print_info,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="hexmind",
    help="[bold bright_green]HexMind[/] — AI Penetration Testing Assistant",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)


def _get_db() -> DatabaseManager:
    """Initialize and return a DatabaseManager using the config path."""
    cfg = get_config()
    dm = DatabaseManager(cfg.db_path)
    dm.init()
    return dm


# ── scan ─────────────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, domain, or CIDR"),
    profile: str = typer.Option(
        "standard", "--profile", "-p",
        help="Scan profile: quick|standard|deep|stealth",
    ),
    no_ai: bool = typer.Option(
        False, "--no-ai",
        help="Run recon tools only, skip AI analysis",
    ),
    allow_private: bool = typer.Option(
        False, "--allow-private",
        help="Allow scanning RFC1918/localhost addresses",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show tool commands and verbose output",
    ),
    tool: Optional[list[str]] = typer.Option(
        None, "--tool", "-t",
        help="Run only this tool (repeatable: -t nmap -t whois)",
    ),
) -> None:
    """Run a full penetration test scan against TARGET."""
    if profile not in SCAN_PROFILES:
        print_error(f"Unknown profile '{profile}'. Use: {', '.join(SCAN_PROFILES)}")
        raise typer.Exit(1)

    validator = TargetValidator()
    try:
        _, normalized, target_type = validator.validate(target, allow_private=allow_private)
    except ValidationError as e:
        print_error(str(e))
        raise typer.Exit(1)

    HEXMIND_DIR.mkdir(parents=True, exist_ok=True)
    dm = _get_db()

    cfg = get_config()
    print_banner(
        target=normalized,
        profile=profile,
        model=cfg.ai.model if not no_ai else "disabled",
    )

    pinfo = SCAN_PROFILES[profile]
    print_dim(f"Profile: {profile.upper()} — {pinfo['description']}")
    print_dim(f"Estimated time: {pinfo['est_minutes']} minutes")
    if no_ai:
        print_warning("AI analysis disabled (--no-ai)")
    console.print()

    try:
        from hexmind.core.session import ScanSession
        session = ScanSession(
            target=normalized,
            profile=profile,
            verbose=verbose,
            no_ai=no_ai,
            allow_private=allow_private,
            specific_tools=tool or [],
        )
        asyncio.run(session.run())
    except NotImplementedError:
        print_warning("Scan engine not yet implemented (Phase 4+). Scaffold verified.")
    except HexMindError as e:
        print_error(str(e))
        raise typer.Exit(1)
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user (Ctrl+C).")
        try:
            with dm.get_db() as db:
                s_repo = ScanRepository(db)
                for s in s_repo.list_all(limit=5):
                    if s.status == "running":
                        s_repo.fail(s.id, "Interrupted by user")
                        print_dim(f"  Scan #{s.id:04d} marked as failed.")
                        break
        except Exception:
            pass
        raise typer.Exit(130)


# ── history ──────────────────────────────────────────────────────────────────

@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Max rows to show"),
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Filter by target value"
    ),
) -> None:
    """List all past scans."""
    dm = _get_db()
    with dm.get_db() as db:
        s_repo = ScanRepository(db)
        f_repo = FindingRepository(db)

        scans = s_repo.list_all(limit=limit)

        if not scans:
            print_info("No scans found. Run [bold]hexmind scan <target>[/] to start.")
            return

        table = Table(
            box=box.ROUNDED,
            border_style="steel_blue",
            show_header=True,
            header_style=f"bold {COLOR_CYAN}",
        )
        table.add_column("#ID",      style=f"bold {COLOR_GREEN}", width=6)
        table.add_column("Target",   style=COLOR_WHITE, min_width=20)
        table.add_column("Profile",  width=10)
        table.add_column("Status",   width=10)
        table.add_column("Risk",     width=6)
        table.add_column("Findings", width=22)
        table.add_column("Duration", width=10)
        table.add_column("Date",     width=12)

        _status_colors = {
            "done":    COLOR_GREEN,
            "running": COLOR_CYAN,
            "failed":  COLOR_RED,
            "pending": COLOR_SLATE,
        }
        _profile_colors = {
            "deep":     COLOR_RED,
            "standard": COLOR_CYAN,
            "quick":    COLOR_SOFT_GREEN,
            "stealth":  COLOR_ORANGE,
        }

        for s in scans:
            if target and s.target and target.lower() not in s.target.value.lower():
                continue

            risk_val = s.risk_score
            if risk_val is None:
                risk_str = "[dim]—[/]"
            elif risk_val >= 70:
                risk_str = f"[bold {COLOR_RED}]{risk_val}[/]"
            elif risk_val >= 40:
                risk_str = f"[{COLOR_ORANGE}]{risk_val}[/]"
            else:
                risk_str = f"[{COLOR_SOFT_GREEN}]{risk_val}[/]"

            sc = _status_colors.get(s.status, COLOR_SLATE)
            status_str = f"[{sc}]{s.status.upper()}[/]"

            pc = _profile_colors.get(s.scan_profile, COLOR_SLATE)
            profile_str = f"[{pc}]{s.scan_profile.upper()}[/]"

            counts = f_repo.count_by_severity(s.id)
            findings_str = (
                f"[{COLOR_RED}]{counts['critical']}C[/] "
                f"[{COLOR_ORANGE}]{counts['high']}H[/] "
                f"[{COLOR_YELLOW}]{counts['medium']}M[/] "
                f"[{COLOR_SOFT_GREEN}]{counts['low']}L[/] "
                f"[{COLOR_SLATE}]{counts['info']}I[/]"
            )

            target_val = s.target.value if s.target else "unknown"
            date_str = s.started_at.strftime("%Y-%m-%d") if s.started_at else "—"

            table.add_row(
                f"#{s.id:04d}",
                target_val,
                profile_str,
                status_str,
                risk_str,
                findings_str,
                s.duration_str,
                date_str,
            )

        console.print(table)


# ── show ─────────────────────────────────────────────────────────────────────

@app.command()
def show(
    scan_id: int = typer.Argument(..., help="Scan ID to display"),
) -> None:
    """Show detailed findings from a specific scan."""
    dm = _get_db()
    with dm.get_db() as db:
        s_repo = ScanRepository(db)
        f_repo = FindingRepository(db)

        scan = s_repo.get_by_id(scan_id)
        if not scan:
            print_error(f"Scan #{scan_id} not found.")
            raise typer.Exit(1)

        target_val = scan.target.value if scan.target else "unknown"
        print_banner(target=target_val, scan_id=scan.id, profile=scan.scan_profile)

        findings = f_repo.get_for_scan(scan_id)
        if not findings:
            print_info("No findings recorded for this scan.")
        else:
            try:
                from hexmind.ui.panels import render_findings_table
                table = render_findings_table([f.to_finding_data() for f in findings])
                console.print(table)
            except (NotImplementedError, ImportError):
                for f in findings:
                    sev_color = SEVERITY_COLORS.get(f.severity.lower(), COLOR_SLATE)
                    console.print(
                        f"  [{sev_color}]{f.severity.upper():<10}[/] "
                        f"[{COLOR_WHITE}]{f.title}[/]"
                    )

        if scan.executive_summary:
            console.print()
            console.print(
                Panel(
                    scan.executive_summary,
                    title="[bold]Executive Summary[/]",
                    border_style="steel_blue",
                    padding=(1, 2),
                )
            )


# ── report ───────────────────────────────────────────────────────────────────

@app.command()
def report(
    scan_id: int = typer.Argument(..., help="Scan ID to export"),
    format: str = typer.Option(
        "html", "--format", "-f", help="Output format: md|html|pdf|json"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Override output file path"
    ),
    no_raw: bool = typer.Option(
        False, "--no-raw", help="Exclude raw tool outputs from report"
    ),
) -> None:
    """Export a scan report in the specified format."""
    if format not in {"md", "html", "pdf", "json"}:
        print_error(f"Invalid format '{format}'. Use: md, html, pdf, json")
        raise typer.Exit(1)

    try:
        from hexmind.reports.exporter import ReportExporter
        cfg = get_config()
        dm  = _get_db()
        with dm.get_db() as db:
            repos = {
                "scan":    ScanRepository(db),
                "tool":    ToolResultRepository(db),
                "finding": FindingRepository(db),
                "ai":      AIConversationRepository(db),
                "target":  TargetRepository(db),
            }
            exporter = ReportExporter(
                db_repos=repos,
                output_dir=output.parent if output else cfg.reports_dir,
            )
            out_path = asyncio.run(
                exporter.export(
                    scan_id=scan_id,
                    format=format,
                    output_path=output,
                    include_raw=not no_raw,
                )
            )
        print_success(f"Report saved: {out_path}")
    except KeyError as e:
        print_error(str(e))
        raise typer.Exit(1)
    except HexMindError as e:
        print_error(str(e))
        raise typer.Exit(1)


# ── targets ──────────────────────────────────────────────────────────────────

@app.command()
def targets() -> None:
    """List all known targets with scan counts."""
    dm = _get_db()
    with dm.get_db() as db:
        t_repo = TargetRepository(db)
        s_repo = ScanRepository(db)

        all_targets = t_repo.list_all()
        if not all_targets:
            print_info("No targets found yet.")
            return

        table = Table(
            box=box.ROUNDED,
            border_style="steel_blue",
            header_style=f"bold {COLOR_CYAN}",
        )
        table.add_column("Target",    style=COLOR_WHITE, min_width=22)
        table.add_column("Type",      width=8)
        table.add_column("Scans",     width=7)
        table.add_column("Last Seen", width=13)
        table.add_column("Tags",      width=20)

        for t in all_targets:
            scans = s_repo.list_for_target(t.id, limit=100)
            last = t.last_seen.strftime("%Y-%m-%d") if t.last_seen else "—"
            type_color = COLOR_CYAN if t.type == "ip" else COLOR_SOFT_GREEN
            table.add_row(
                t.value,
                f"[{type_color}]{t.type}[/]",
                str(len(scans)),
                last,
                ", ".join(t.tags) if t.tags else "—",
            )

        console.print(table)


# ── search ───────────────────────────────────────────────────────────────────

@app.command()
def search(
    query: str = typer.Argument(..., help="Search query or CVE ID"),
    cve: bool = typer.Option(False, "--cve", help="Look up a specific CVE ID"),
) -> None:
    """Run a standalone web search or CVE lookup."""
    try:
        if cve:
            from hexmind.search.cve_lookup import CVELookup
            lookup = CVELookup()
            result = asyncio.run(lookup.lookup(query))
            if result:
                print_success(f"CVE found: {result.cve_id}")
                print_info(f"CVSS: {result.cvss_score} | Severity: {result.severity.upper()}")
                snippet = result.description
                print_dim(snippet[:300] + "..." if len(snippet) > 300 else snippet)
            else:
                print_warning(f"No data found for: {query}")
        else:
            from hexmind.search.duckduckgo import DuckDuckGoSearch
            ddg = DuckDuckGoSearch()
            results = asyncio.run(ddg.search(query))
            if not results:
                print_warning("No results found.")
                return
            for i, r in enumerate(results, 1):
                console.print(f"[{COLOR_CYAN}]{i}.[/] [{COLOR_WHITE}]{r.title}[/]")
                console.print(f"   [{COLOR_SLATE}]{r.url}[/]")
                console.print(f"   {r.snippet[:120]}...")
                console.print()
    except NotImplementedError:
        print_warning("Search modules not yet implemented (Phase 7).")


# ── compare ──────────────────────────────────────────────────────────────────

@app.command()
def compare(
    scan_id_1: int = typer.Argument(..., help="First scan ID"),
    scan_id_2: int = typer.Argument(..., help="Second scan ID"),
) -> None:
    """Compare findings between two scans."""
    dm = _get_db()
    with dm.get_db() as db:
        s_repo = ScanRepository(db)
        f_repo = FindingRepository(db)

        s1 = s_repo.get_by_id(scan_id_1)
        s2 = s_repo.get_by_id(scan_id_2)

        if not s1:
            print_error(f"Scan #{scan_id_1} not found.")
            raise typer.Exit(1)
        if not s2:
            print_error(f"Scan #{scan_id_2} not found.")
            raise typer.Exit(1)

        f1_titles = {f.title for f in f_repo.get_for_scan(scan_id_1)}
        f2_titles = {f.title for f in f_repo.get_for_scan(scan_id_2)}

        new_findings = f2_titles - f1_titles
        resolved     = f1_titles - f2_titles
        persisted    = f1_titles & f2_titles

        print_phase_separator(f"COMPARE #{scan_id_1} → #{scan_id_2}")

        console.print(f"\n[bold {COLOR_RED}]New findings[/] ({len(new_findings)}):")
        for t in sorted(new_findings):
            console.print(f"  [{COLOR_RED}]+[/] {t}")

        console.print(f"\n[bold {COLOR_SOFT_GREEN}]Resolved[/] ({len(resolved)}):")
        for t in sorted(resolved):
            console.print(f"  [{COLOR_SOFT_GREEN}]-[/] {t}")

        console.print(f"\n[bold {COLOR_SLATE}]Unchanged[/] ({len(persisted)}):")
        for t in sorted(persisted):
            console.print(f"  [{COLOR_SLATE}]=[/] {t}")


# ── config ───────────────────────────────────────────────────────────────────

@app.command("config")
def config_cmd(
    show: bool = typer.Option(False, "--show", help="Print current config"),
    set_: Optional[str] = typer.Option(
        None, "--set",
        help="Set config value as section.key=value (e.g. --set ai.model=llama3)",
    ),
    reset: bool = typer.Option(False, "--reset", help="Reset config to defaults"),
) -> None:
    """View or modify HexMind configuration."""
    import json

    cfg = get_config()

    if show or (not set_ and not reset):
        console.print(
            Panel(
                json.dumps(cfg.model_dump(), indent=2, default=str),
                title="[bold]HexMind Configuration[/]",
                border_style="steel_blue",
                subtitle=str(cfg.db_path),
            )
        )

    if set_:
        try:
            key_part, val_part = set_.split("=", 1)
            parts = key_part.strip().split(".")
            if len(parts) != 2:
                raise ValueError
        except ValueError:
            print_error("Format: --set section.key=value  (e.g. --set ai.model=llama3)")
            raise typer.Exit(1)

        section, key = parts
        print_warning(
            f"Config persistence not yet implemented. "
            f"Would set {section}.{key}={val_part}"
        )

    if reset:
        print_warning(
            "Reset not yet implemented. "
            "Delete ~/.hexmind/config.toml manually to reset to defaults."
        )


# ── doctor ───────────────────────────────────────────────────────────────────

@app.command()
def doctor() -> None:
    """Check system dependencies, tool availability, and Ollama status."""
    import importlib.metadata as meta

    import httpx

    print_banner()
    print_phase_separator("SYSTEM HEALTH CHECK")
    console.print()

    cfg = get_config()
    all_ok = True

    # ── Python environment ──────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Python Environment[/]")

    py_ver = sys.version.split()[0]
    py_ok = tuple(int(x) for x in py_ver.split(".")[:2]) >= (3, 11)
    py_icon = f"[{COLOR_GREEN}]✓[/]" if py_ok else f"[{COLOR_RED}]✗[/]"
    console.print(
        f"  {py_icon}  Python {py_ver}"
        + ("" if py_ok else f"  [{COLOR_RED}]requires 3.11+[/]")
    )

    packages = {
        "typer":      "typer",
        "rich":       "rich",
        "sqlalchemy": "sqlalchemy",
        "httpx":      "httpx",
        "pydantic":   "pydantic",
    }
    for display, mod_name in packages.items():
        try:
            ver = meta.version(mod_name)
            console.print(f"  [{COLOR_GREEN}]✓[/]  {display} {ver}")
        except Exception:
            console.print(f"  [{COLOR_RED}]✗[/]  {display} [dim]not found[/]")
            all_ok = False

    console.print()

    # ── Recon tools ─────────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Recon Tools[/]")

    tool_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tool_table.add_column("icon",   width=3)
    tool_table.add_column("name",   width=12, style=f"bold {COLOR_WHITE}")
    tool_table.add_column("path",   style=COLOR_SLATE)
    tool_table.add_column("status", width=18)

    for tool_name, binary in TOOL_BINARIES.items():
        path = shutil.which(binary)
        if path:
            icon   = f"[{COLOR_GREEN}]✓[/]"
            status = f"[{COLOR_GREEN}]found[/]"
            path_s = path
        else:
            icon   = f"[{COLOR_RED}]✗[/]"
            status = f"[{COLOR_RED}]not found[/]"
            path_s = f"[dim]install: sudo apt install {binary}[/]"
            all_ok = False
        tool_table.add_row(icon, tool_name, path_s, status)

    console.print(tool_table)
    console.print()

    # ── Wordlist ─────────────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Wordlist[/]")

    if WORDLIST_PATH.exists():
        line_count = sum(1 for ln in WORDLIST_PATH.open() if ln.strip())
        console.print(
            f"  [{COLOR_GREEN}]✓[/]  {WORDLIST_PATH}"
            f"  [{COLOR_SLATE}]({line_count} paths)[/]"
        )
    else:
        console.print(f"  [{COLOR_RED}]✗[/]  Wordlist missing: {WORDLIST_PATH}")
        all_ok = False

    console.print()

    # ── Reports ──────────────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Reports Directory[/]")
    rdir = cfg.reports_dir
    if rdir.exists():
        reports = list(rdir.glob("report_scan_*"))
        console.print(
            f"  [{COLOR_GREEN}]✓[/]  {rdir}  "
            f"([dim]{len(reports)} report(s)[/])"
        )
    else:
        rdir.mkdir(parents=True, exist_ok=True)
        console.print(
            f"  [{COLOR_GREEN}]✓[/]  {rdir}  "
            f"([dim]created[/])"
        )
    console.print()

    # ── Ollama / AI ─────────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]AI Engine (Ollama)[/]")

    ollama_url = cfg.ai.base_url
    model_name = cfg.ai.model

    try:
        resp = httpx.get(f"{ollama_url}/api/tags", timeout=3.0)
        resp.raise_for_status()
        tags_data = resp.json()
        models = [m["name"] for m in tags_data.get("models", [])]

        console.print(f"  [{COLOR_GREEN}]✓[/]  Ollama running at {ollama_url}")

        model_found = any(
            m.startswith(model_name) or model_name in m for m in models
        )
        if model_found:
            matched = next(m for m in models if m.startswith(model_name) or model_name in m)
            console.print(f"  [{COLOR_GREEN}]✓[/]  Model '{matched}' available")
        else:
            console.print(
                f"  [{COLOR_RED}]✗[/]  Model '{model_name}' not found"
                f"  [dim]run: ollama pull {model_name}[/]"
            )
            all_ok = False
            if models:
                print_dim(f"    Available models: {', '.join(models[:5])}")

    except httpx.ConnectError:
        console.print(
            f"  [{COLOR_RED}]✗[/]  Ollama not running at {ollama_url}"
            f"  [dim]run: ollama serve[/]"
        )
        all_ok = False
    except Exception as e:
        console.print(f"  [{COLOR_RED}]✗[/]  Ollama error: {e}")
        all_ok = False

    console.print()

    # ── Database ─────────────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Database[/]")

    try:
        HEXMIND_DIR.mkdir(parents=True, exist_ok=True)
        dm = _get_db()
        size_mb = dm.get_db_size_mb()
        console.print(f"  [{COLOR_GREEN}]✓[/]  SQLite DB at {cfg.db_path}")
        console.print(f"  [{COLOR_GREEN}]✓[/]  Size: {size_mb:.2f} MB")
        dm.close()
    except Exception as e:
        console.print(f"  [{COLOR_RED}]✗[/]  Database error: {e}")
        all_ok = False

    console.print()

    # ── Version roadmap ──────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Version Roadmap[/]")

    for ver, desc in VERSION_ROADMAP.items():
        is_current = ver == HEXMIND_VERSION
        icon  = f"[bold {COLOR_GREEN}]►[/]" if is_current else f"[{COLOR_SLATE}]○[/]"
        style = f"bold {COLOR_WHITE}" if is_current else COLOR_SLATE
        console.print(f"  {icon}  [{style}]v{ver}[/]  [dim]{desc}[/]")

    console.print()

    # ── Scan statistics ──────────────────────────────────────────────────────
    console.print(f"[bold {COLOR_CYAN}]Scan Statistics[/]")

    try:
        dm_stats = _get_db()
        with dm_stats.get_db() as db:
            s_count = len(ScanRepository(db).list_all(limit=9999))
            t_count = len(TargetRepository(db).list_all())
        stats_mb = dm_stats.get_db_size_mb()
        dm_stats.close()
        console.print(
            f"  [{COLOR_GREEN}]✓[/]  "
            f"{s_count} scan(s) · {t_count} unique target(s) · "
            f"{stats_mb:.2f} MB"
        )
    except Exception as e:
        console.print(f"  [{COLOR_SLATE}]—[/]  Stats unavailable: {e}")

    console.print()

    # ── Final verdict ────────────────────────────────────────────────────────
    console.rule(style="steel_blue")
    if all_ok:
        console.print(f"[bold {COLOR_GREEN}]✓  All systems operational. HexMind is ready.[/]")
    else:
        console.print(
            f"[bold {COLOR_ORANGE}]⚠  Some checks failed. "
            f"Install missing dependencies before scanning.[/]"
        )
    console.print()


# ── App callback ──────────────────────────────────────────────────────────────

def _version_callback(value: bool) -> None:
    if value:
        console.print(
            f"[bold {COLOR_GREEN}]HexMind[/] "
            f"v{HEXMIND_VERSION} [{HEXMIND_CODENAME}]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version", "-V",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """HexMind — AI Penetration Testing Assistant."""
    HEXMIND_DIR.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    app()
