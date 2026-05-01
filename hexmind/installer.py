"""Smart installer for HexMind — detects platform and installs all dependencies.

Invoke as:  python3 -m hexmind.installer [--detect-only]
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ── Icons / colors ────────────────────────────────────────────────────────────

_OK   = "[bright_green]✓[/]"
_WARN = "[yellow]![/]"
_FAIL = "[bright_red]✗[/]"

_GREEN  = "bright_green"
_YELLOW = "yellow"
_RED    = "bright_red"
_CYAN   = "cyan"
_WHITE  = "bright_white"
_SLATE  = "bright_black"

# ── Tool → package name per distro (None = not in repos) ─────────────────────

_TOOL_PACKAGES: dict[str, dict[str, Optional[str]]] = {
    "nmap":     {"apt": "nmap",     "pacman": "nmap",     "dnf": "nmap"},
    "whois":    {"apt": "whois",    "pacman": "whois",    "dnf": "whois"},
    "dig":      {"apt": "dnsutils", "pacman": "bind",     "dnf": "bind-utils"},
    "curl":     {"apt": "curl",     "pacman": "curl",     "dnf": "curl"},
    "whatweb":  {"apt": "whatweb",  "pacman": "whatweb",  "dnf": None},
    "nikto":    {"apt": "nikto",    "pacman": "nikto",    "dnf": None},
    "sslscan":  {"apt": "sslscan",  "pacman": "sslscan",  "dnf": None},
    "gobuster": {"apt": "gobuster", "pacman": "gobuster", "dnf": None},
}

_MANUAL_HINTS: dict[str, str] = {
    "whatweb":  "https://github.com/urbanadventurer/WhatWeb",
    "nikto":    "https://github.com/sullo/nikto",
    "sslscan":  "https://github.com/rbsec/sslscan",
    "gobuster": "https://github.com/OJ/gobuster/releases",
}

_REQUIRED_TOOLS = {"nmap", "curl", "dig"}

_CONFIG_TEMPLATE = """\
[ai]
model = "mistral"
base_url = "http://localhost:11434"
temperature = 0.1
max_tokens = 4096
stream = true

[scan]
max_iterations = 5
timeout = 300
default_profile = "standard"
allow_private = false
parallel_tools = true

[db]
path = "~/.hexmind/hexmind.db"

[tools]
nmap = "nmap"
whois = "whois"
whatweb = "whatweb"
nikto = "nikto"
dig = "dig"
curl = "curl"
gobuster = "gobuster"
sslscan = "sslscan"

[search]
ddg_rate_limit = 2.0
nvd_rate_limit = 6.0
max_results = 5

[reports]
output_dir = "~/hexmind-reports"
default_format = "html"
include_raw = true

[ui]
stream_ai_output = true
show_commands = true
verbose = false
"""

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class PlatformInfo:
    os_name:     str
    os_id:       str
    os_version:  str
    arch:        str
    pkg_manager: str
    python_ok:   bool


@dataclass
class StepResult:
    label:   str
    status:  str   # "ok" | "warn" | "fail" | "skip"
    detail:  str = ""


# ── Platform detection ────────────────────────────────────────────────────────

_APT_IDS    = {"ubuntu", "debian", "kali", "parrot", "linuxmint", "pop", "raspbian"}
_PACMAN_IDS = {"arch", "manjaro", "endeavouros", "garuda"}
_DNF_IDS    = {"fedora", "rhel", "centos", "rocky", "almalinux"}


def detect_platform() -> PlatformInfo:
    """Parse /etc/os-release and platform.machine() to identify the system."""
    os_name = "Unknown"
    os_id   = "unknown"
    os_ver  = ""

    os_release = Path("/etc/os-release")
    if os_release.exists():
        data: dict[str, str] = {}
        for line in os_release.read_text().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip().strip('"')
        os_name = data.get("NAME", "Unknown")
        os_id   = data.get("ID", "unknown").lower()
        os_ver  = data.get("VERSION_ID", "")

    # Derive package manager from distro ID, then fall back to which()
    if os_id in _APT_IDS or "ubuntu" in os_id or "debian" in os_id:
        pkg_mgr = "apt"
    elif os_id in _PACMAN_IDS:
        pkg_mgr = "pacman"
    elif os_id in _DNF_IDS:
        pkg_mgr = "dnf"
    elif shutil.which("apt-get"):
        pkg_mgr = "apt"
    elif shutil.which("pacman"):
        pkg_mgr = "pacman"
    elif shutil.which("dnf"):
        pkg_mgr = "dnf"
    elif shutil.which("yum"):
        pkg_mgr = "yum"
    else:
        pkg_mgr = "unknown"

    return PlatformInfo(
        os_name    = os_name,
        os_id      = os_id,
        os_version = os_ver,
        arch       = platform.machine(),
        pkg_manager= pkg_mgr,
        python_ok  = sys.version_info >= (3, 11),
    )


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _run(cmd: list[str], *, capture: bool = True) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    r = subprocess.run(cmd, capture_output=capture, text=True)
    return r.returncode, r.stdout, r.stderr


def _has_sudo() -> bool:
    """Return True if sudo is available without a password prompt."""
    rc, _, _ = _run(["sudo", "-n", "true"])
    return rc == 0


def _section(title: str) -> None:
    console.rule(f"[bold {_CYAN}]{title}[/]", style="steel_blue")
    console.print()


def _row(status: str, label: str, detail: str = "") -> None:
    icon = {
        "ok":   f"  {_OK} ",
        "warn": f"  {_WARN} ",
        "fail": f"  {_FAIL} ",
        "skip": f"  [{_SLATE}]—[/] ",
    }.get(status, "  ? ")
    color = {
        "ok":   _GREEN,
        "warn": _YELLOW,
        "fail": _RED,
        "skip": _SLATE,
    }.get(status, _WHITE)
    line = f"{icon}[{color}]{label}[/]"
    if detail:
        line += f"  [{_SLATE}]{detail}[/]"
    console.print(line)


# ── Banner ────────────────────────────────────────────────────────────────────

_ASCII = """\
  ██╗  ██╗███████╗██╗  ██╗███╗   ███╗██╗███╗   ██╗██████╗
  ██║  ██║██╔════╝╚██╗██╔╝████╗ ████║██║████╗  ██║██╔══██╗
  ███████║█████╗   ╚███╔╝ ██╔████╔██║██║██╔██╗ ██║██║  ██║
  ██╔══██║██╔══╝   ██╔██╗ ██║╚██╔╝██║██║██║╚██╗██║██║  ██║
  ██║  ██║███████╗██╔╝ ██╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝"""


def _print_banner() -> None:
    content = Text()
    content.append(_ASCII, style=f"bold {_GREEN}")
    content.append("\n")
    content.append(
        "Smart Installer — AI Penetration Testing Assistant",
        style=f"dim {_CYAN}",
    )
    try:
        from hexmind.constants import HEXMIND_VERSION
        subtitle = f"v{HEXMIND_VERSION}"
    except Exception:
        subtitle = ""
    console.print(
        Panel(content, border_style="steel_blue", padding=(0, 2), subtitle=subtitle, subtitle_align="right")
    )
    console.print()


# ── Step 1: Platform detection display ───────────────────────────────────────

def _display_platform(info: PlatformInfo) -> None:
    _section("Platform Detection")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("key",   width=18, style=f"dim {_WHITE}")
    table.add_column("value", style=_WHITE)

    arch_ok = info.arch in {"x86_64", "aarch64", "armv7l"}
    table.add_row("OS",          f"{info.os_name} {info.os_version}".strip())
    table.add_row("Architecture", info.arch + ("" if arch_ok else f"  [{_YELLOW}]untested[/]"))
    table.add_row("Pkg manager",  info.pkg_manager if info.pkg_manager != "unknown"
                  else f"[{_RED}]unknown — installs will be skipped[/]")
    table.add_row("Python",       py_ver + (
        f"  [{_GREEN}]✓[/]" if info.python_ok else f"  [{_RED}]requires 3.11+[/]"
    ))

    console.print(table)

    if not info.python_ok:
        console.print(
            f"  [{_YELLOW}]![/]  Python {py_ver} is below the required 3.11. "
            "Upgrade before using HexMind."
        )
    console.print()


# ── Step 2: System tools ──────────────────────────────────────────────────────

def _install_system_tools(
    info: PlatformInfo,
    dry_run: bool,
) -> list[StepResult]:
    """Install missing recon tools via the system package manager."""
    _section("System Tools")
    results: list[StepResult] = []

    pkg_mgr = info.pkg_manager
    if pkg_mgr not in {"apt", "pacman", "dnf", "yum"}:
        console.print(
            f"  {_WARN}  Unknown package manager — skipping system tool installs."
        )
        console.print()
        return []

    # yum → use dnf table
    lookup_mgr = "dnf" if pkg_mgr == "yum" else pkg_mgr

    to_install: list[tuple[str, str]] = []   # (binary_name, pkg_name)

    for binary, pkgs in _TOOL_PACKAGES.items():
        pkg_name = pkgs.get(lookup_mgr)

        if shutil.which(binary):
            _row("ok", binary, "already installed")
            results.append(StepResult(binary, "ok", "already installed"))
            continue

        if pkg_name is None:
            hint = _MANUAL_HINTS.get(binary, "")
            msg = f"not in {pkg_mgr} repos"
            if hint:
                msg += f" — {hint}"
            _row("warn", binary, msg)
            results.append(StepResult(binary, "warn", f"not in repos — install manually"))
            continue

        if dry_run:
            _row("skip", binary, f"would install: {pkg_mgr} install {pkg_name}")
            results.append(StepResult(binary, "skip", f"{pkg_mgr} install {pkg_name}"))
        else:
            to_install.append((binary, pkg_name))

    if not dry_run and to_install:
        pkg_names = [p for _, p in to_install]
        binaries  = [b for b, _ in to_install]

        if not _has_sudo():
            console.print(
                f"\n  {_WARN}  sudo is required to install: "
                + ", ".join(pkg_names)
                + "\n    Run with sudo access or install manually."
            )
            for b, p in to_install:
                required = b in _REQUIRED_TOOLS
                status   = "fail" if required else "warn"
                _row(status, b, f"skipped — no sudo")
                results.append(StepResult(b, status, "skipped — no sudo"))
        else:
            console.print(
                f"\n  Installing: [{_CYAN}]{', '.join(pkg_names)}[/] "
                f"via [{_WHITE}]{pkg_mgr}[/]…"
            )
            if pkg_mgr == "apt":
                rc, _, err = _run(["sudo", "apt-get", "install", "-y"] + pkg_names)
            elif pkg_mgr == "pacman":
                rc, _, err = _run(["sudo", "pacman", "-S", "--noconfirm"] + pkg_names)
            else:
                rc, _, err = _run(["sudo", pkg_mgr, "install", "-y"] + pkg_names)

            for b, _ in to_install:
                if rc == 0 or shutil.which(b):
                    _row("ok", b, "installed")
                    results.append(StepResult(b, "ok", "installed"))
                else:
                    required = b in _REQUIRED_TOOLS
                    status   = "fail" if required else "warn"
                    _row(status, b, "install failed")
                    results.append(StepResult(b, status, "install failed"))

    console.print()
    return results


# ── Step 3: Ollama ────────────────────────────────────────────────────────────

def _install_ollama(dry_run: bool) -> list[StepResult]:
    """Install Ollama if missing, start the service, and pull mistral."""
    _section("Ollama AI Engine")
    results: list[StepResult] = []

    # — Install —
    if shutil.which("ollama"):
        _row("ok", "ollama", "already installed")
        results.append(StepResult("ollama", "ok", "already installed"))
    elif dry_run:
        _row("skip", "ollama", "would run: curl -fsSL https://ollama.ai/install.sh | sh")
        results.append(StepResult("ollama", "skip", "would install via official script"))
    else:
        if not shutil.which("curl"):
            _row("fail", "ollama", "curl is required but not installed — cannot download")
            results.append(StepResult("ollama", "fail", "curl missing"))
            console.print()
            return results

        console.print(f"  Downloading and running Ollama installer…")
        rc = subprocess.run(
            "curl -fsSL https://ollama.ai/install.sh | sh",
            shell=True,
        ).returncode
        if rc == 0 and shutil.which("ollama"):
            _row("ok", "ollama", "installed")
            results.append(StepResult("ollama", "ok", "installed"))
        else:
            _row("fail", "ollama", "install script failed")
            results.append(StepResult("ollama", "fail", "install script failed"))
            console.print()
            return results

    # — Start service —
    if dry_run:
        _row("skip", "ollama service", "would start: systemctl --user start ollama")
        results.append(StepResult("ollama service", "skip", "would start service"))
    else:
        if shutil.which("systemctl"):
            rc, _, _ = _run(["systemctl", "--user", "is-active", "--quiet", "ollama"])
            if rc == 0:
                _row("ok", "ollama service", "already running")
                results.append(StepResult("ollama service", "ok", "already running"))
            else:
                rc2, _, _ = _run(["systemctl", "--user", "start", "ollama"])
                if rc2 == 0:
                    _row("ok", "ollama service", "started via systemctl")
                    results.append(StepResult("ollama service", "ok", "started"))
                else:
                    # Fall back to background serve
                    subprocess.Popen(
                        ["ollama", "serve"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    _row("ok", "ollama service", "started via 'ollama serve &'")
                    results.append(StepResult("ollama service", "ok", "background serve"))
        else:
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _row("ok", "ollama service", "started via 'ollama serve &'")
            results.append(StepResult("ollama service", "ok", "background serve"))

    # — Pull mistral —
    if dry_run:
        _row("skip", "mistral model", "would run: ollama pull mistral")
        results.append(StepResult("mistral model", "skip", "would pull"))
    else:
        console.print(f"  Pulling mistral model (this may take a few minutes)…")
        rc, _, _ = _run(["ollama", "pull", "mistral"], capture=False)
        if rc == 0:
            _row("ok", "mistral model", "ready")
            results.append(StepResult("mistral model", "ok", "pulled"))
        else:
            _row("warn", "mistral model", "pull failed — run 'ollama pull mistral' manually")
            results.append(StepResult("mistral model", "warn", "pull failed"))

    console.print()
    return results


# ── Step 4: Config setup ──────────────────────────────────────────────────────

def _setup_config(dry_run: bool) -> list[StepResult]:
    """Create ~/.hexmind/ and ~/hexmind-reports/, copy config template."""
    _section("HexMind Config")
    results: list[StepResult] = []

    hexmind_dir  = Path("~/.hexmind").expanduser()
    reports_dir  = Path("~/hexmind-reports").expanduser()
    config_path  = hexmind_dir / "config.toml"

    for d, label in [(hexmind_dir, "~/.hexmind"), (reports_dir, "~/hexmind-reports")]:
        if d.exists():
            _row("ok", label, "already exists")
            results.append(StepResult(label, "ok", "already exists"))
        elif dry_run:
            _row("skip", label, f"would create {d}")
            results.append(StepResult(label, "skip", f"would mkdir {d}"))
        else:
            d.mkdir(parents=True, exist_ok=True)
            _row("ok", label, "created")
            results.append(StepResult(label, "ok", "created"))

    if config_path.exists():
        _row("ok", "config.toml", "already exists — not overwritten")
        results.append(StepResult("config.toml", "ok", "already exists"))
    elif dry_run:
        _row("skip", "config.toml", f"would write {config_path}")
        results.append(StepResult("config.toml", "skip", f"would write {config_path}"))
    else:
        config_path.write_text(_CONFIG_TEMPLATE)
        _row("ok", "config.toml", f"written to {config_path}")
        results.append(StepResult("config.toml", "ok", f"written to {config_path}"))

    console.print()
    return results


# ── Step 5: PATH setup ────────────────────────────────────────────────────────

def _setup_path(dry_run: bool) -> list[StepResult]:
    """Ensure ~/.local/bin is on PATH in shell rc files."""
    _section("PATH Setup")
    results: list[StepResult] = []

    if shutil.which("hexmind"):
        _row("ok", "hexmind", f"already on PATH ({shutil.which('hexmind')})")
        results.append(StepResult("hexmind PATH", "ok", "already on PATH"))
        console.print()
        return results

    local_bin    = Path("~/.local/bin").expanduser()
    path_line    = '\nexport PATH="$HOME/.local/bin:$PATH"\n'
    shell_rcs    = [Path("~/.bashrc").expanduser(), Path("~/.zshrc").expanduser()]
    updated: list[str] = []

    for rc_file in shell_rcs:
        if not rc_file.exists():
            continue
        content = rc_file.read_text()
        if ".local/bin" in content:
            _row("ok", rc_file.name, "PATH already set")
            results.append(StepResult(rc_file.name, "ok", "PATH already set"))
        elif dry_run:
            _row("skip", rc_file.name, f"would append: export PATH=$HOME/.local/bin:$PATH")
            results.append(StepResult(rc_file.name, "skip", "would add PATH"))
        else:
            rc_file.open("a").write(path_line)
            _row("ok", rc_file.name, "PATH entry added")
            results.append(StepResult(rc_file.name, "ok", "PATH entry added"))
            updated.append(rc_file.name)

    if updated:
        console.print(
            f"\n  [{_YELLOW}]![/]  Reload your shell to apply PATH changes:\n"
            "      source ~/.bashrc  (or restart terminal)"
        )
        results.append(StepResult("reload shell", "warn", "source ~/.bashrc to apply PATH"))

    console.print()
    return results


# ── Step 6: Doctor ───────────────────────────────────────────────────────────

def _run_doctor(dry_run: bool) -> list[StepResult]:
    """Run the hexmind doctor command as a final health check."""
    _section("System Health Check")
    results: list[StepResult] = []

    if dry_run:
        _row("skip", "doctor", "would run: hexmind doctor")
        results.append(StepResult("doctor", "skip", "skipped in detect-only mode"))
        console.print()
        return results

    # Try hexmind directly; fall back to python -m hexmind.cli doctor
    cmd = (
        ["hexmind", "doctor"]
        if shutil.which("hexmind")
        else [sys.executable, "-m", "hexmind.cli", "doctor"]
    )

    rc = subprocess.run(cmd).returncode
    if rc == 0:
        results.append(StepResult("doctor", "ok", "health check passed"))
    else:
        results.append(StepResult("doctor", "warn", "health check reported issues"))

    console.print()
    return results


# ── Summary box ───────────────────────────────────────────────────────────────

def _print_summary(all_results: list[StepResult], dry_run: bool) -> None:
    ok_count   = sum(1 for r in all_results if r.status == "ok")
    warn_count = sum(1 for r in all_results if r.status in {"warn", "skip"})
    fail_count = sum(1 for r in all_results if r.status == "fail")

    lines: list[Text] = []

    title = "DRY RUN — Detection Only" if dry_run else "Installation Complete"
    lines.append(Text(title, style=f"bold {_GREEN}"))
    lines.append(Text(""))
    lines.append(Text.assemble(
        (f"  {ok_count} ", f"bold {_GREEN}"),
        ("installed/ready   ", _GREEN),
        (f"{warn_count} ", f"bold {_YELLOW}"),
        ("warnings/skipped   ", _YELLOW),
        (f"{fail_count} ", f"bold {_RED}" if fail_count else f"bold {_SLATE}"),
        ("failed", _RED if fail_count else _SLATE),
    ))

    if fail_count:
        lines.append(Text(""))
        lines.append(Text("Failed items:", style=f"bold {_RED}"))
        for r in all_results:
            if r.status == "fail":
                lines.append(Text(f"  ✗  {r.label}  {r.detail}", style=_RED))

    skipped = [r for r in all_results if r.status == "warn"]
    if skipped:
        lines.append(Text(""))
        lines.append(Text("Manual installs needed:", style=f"bold {_YELLOW}"))
        for r in skipped:
            lines.append(Text(f"  !  {r.label}  {r.detail}", style=_YELLOW))

    if not dry_run and fail_count == 0:
        lines.append(Text(""))
        lines.append(Text.assemble(
            ("HexMind is ready.  Run: ", _SLATE),
            ("hexmind scan <target>", f"bold {_GREEN}"),
        ))

    content = Text("\n").join(lines)
    border  = _RED if fail_count else (_YELLOW if warn_count else _GREEN)
    console.print(Panel(content, border_style=border, padding=(1, 2)))


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    """Run the HexMind smart installer. Returns 0 on success, 1 on hard failure."""
    parser = argparse.ArgumentParser(
        prog="python3 -m hexmind.installer",
        description="HexMind Smart Installer",
    )
    parser.add_argument(
        "--detect-only",
        action="store_true",
        help="Detect platform and show what would be installed — no changes made",
    )
    args = parser.parse_args(argv)
    dry_run = args.detect_only

    _print_banner()

    if dry_run:
        console.print(
            f"  [{_YELLOW}]detect-only mode[/]  — no system changes will be made\n"
        )

    info = detect_platform()
    _display_platform(info)

    all_results: list[StepResult] = []
    all_results += _install_system_tools(info, dry_run)
    all_results += _install_ollama(dry_run)
    all_results += _setup_config(dry_run)
    all_results += _setup_path(dry_run)
    all_results += _run_doctor(dry_run)

    _print_summary(all_results, dry_run)

    hard_failures = [r for r in all_results if r.status == "fail"
                     and r.label in _REQUIRED_TOOLS]
    return 1 if hard_failures else 0


if __name__ == "__main__":
    sys.exit(main())
