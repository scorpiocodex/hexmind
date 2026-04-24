# HexMind v0.1.0-alpha — AI Penetration Testing Assistant

> Fully local, CLI-based AI pentesting assistant powered by Ollama.
> No cloud. No API keys. Everything runs on your machine.

`Python 3.11+` · `SQLite` · `Ollama/Mistral` · `Rich TUI` · `MIT License`

---

## Features

- **8 recon runners** executing in async parallel tiers (whois, dig, curl, nmap, whatweb, sslscan, nikto, gobuster)
- **Local AI analysis** via Ollama + Mistral — 100% offline, zero data leaves your machine
- **Agentic loop** — AI can request follow-up scans mid-analysis and converge on findings
- **Full scan history** stored in SQLite across 5 linked tables (targets, scans, tool_results, findings, ai_conversations)
- **Report export** — Markdown, HTML, PDF (WeasyPrint), and JSON
- **CVE lookup** via CIRCL.lu + NVD fallback (no API key required)
- **Web search** via DuckDuckGo (no API key required)
- **Scan comparison** — diff findings between any two scan IDs

---

## Prerequisites

| Tool | Install | Required? |
|------|---------|-----------|
| Python 3.11+ | `sudo apt install python3.11` | Yes |
| nmap | `sudo apt install nmap` | Yes |
| whois | `sudo apt install whois` | Yes |
| dig | `sudo apt install dnsutils` | Yes |
| curl | `sudo apt install curl` | Yes |
| whatweb | `sudo apt install whatweb` | Recommended |
| nikto | `sudo apt install nikto` | Recommended |
| sslscan | `sudo apt install sslscan` | Recommended |
| gobuster | `sudo apt install gobuster` | Optional (deep profile) |
| Ollama | `curl https://ollama.ai/install.sh \| sh` | Yes (AI analysis) |

---

## Installation

```bash
git clone https://github.com/scorpiocodex/hexmind.git
cd hexmind
pip install -e .
ollama pull mistral
hexmind doctor
```

---

## Usage

| Command | Description |
|---------|-------------|
| `hexmind scan <target>` | Run a full scan with the standard profile |
| `hexmind scan <target> --profile quick` | Fast 2–5 min scan |
| `hexmind scan <target> --profile deep` | Thorough scan with gobuster + vuln scripts |
| `hexmind scan <target> --no-ai` | Recon only, skip AI analysis |
| `hexmind scan <target> --tool nmap --tool whois` | Run specific tools only |
| `hexmind history` | List all past scans |
| `hexmind history --target example.com` | Filter history by target |
| `hexmind show <id>` | Show findings for a specific scan |
| `hexmind report <id> --format html` | Export HTML report |
| `hexmind report <id> --format pdf` | Export PDF report |
| `hexmind report <id> --format md` | Export Markdown report |
| `hexmind report <id> --format json` | Export JSON report |
| `hexmind compare <id1> <id2>` | Diff findings between two scans |
| `hexmind targets` | List all known targets |
| `hexmind search <query>` | DuckDuckGo web search |
| `hexmind search <cve-id> --cve` | CVE detail lookup |
| `hexmind doctor` | Check all dependencies and system health |
| `hexmind --version` | Show version |

### Example output

```
hexmind scan scanme.nmap.org --profile quick

 ██╗  ██╗███████╗██╗  ██╗███╗   ███╗██╗███╗   ██╗██████╗
 ██║  ██║██╔════╝╚██╗██╔╝████╗ ████║██║████╗  ██║██╔══██╗
 ███████║█████╗   ╚███╔╝ ██╔████╔██║██║██╔██╗ ██║██║  ██║
 ██╔══██║██╔══╝   ██╔██╗ ██║╚██╔╝██║██║██║╚██╗██║██║  ██║
 ██║  ██║███████╗██╔╝ ██╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝

  Target  › scanme.nmap.org
  Profile › QUICK
  Scan ID › #0012  DB › ~/.hexmind/hexmind.db

  ─── RECON PHASE ───
  [✓] whois          3.2s
  [✓] dig            0.8s
  [✓] nmap           4.1s
  ─── AI ANALYSIS ───
  [✓] Pass 1/1 complete — 3 findings
```

---

## Scan Profiles

| Profile | Tools | AI Passes | Est. Time | Use Case |
|---------|-------|-----------|-----------|----------|
| `quick` | nmap (fast) + whois + dig | 1 | 2–5 min | Quick triage |
| `standard` | All tools except gobuster | 2 | 15–30 min | Default pentesting (default) |
| `deep` | All tools + vuln scripts + gobuster | 3 | 60–120 min | Full engagement |
| `stealth` | Low-noise timing, minimal footprint | 2 | 60–90 min | Evasion-conscious scans |

---

## Project Structure

```
hexmind/
├── ai/              # OllamaEngine, AgenticLoop, ContextBuilder, AIParser
├── core/            # ScanSession, RateLimiter, TargetValidator, exceptions
├── db/              # SQLAlchemy models, DatabaseManager, repositories
├── recon/           # 8 tool runners + ReconOrchestrator
├── reports/         # Jinja2 templates, ReportExporter, PDFRenderer
├── search/          # DuckDuckGoSearch, CVELookup
├── ui/              # Rich console, banner, panels, spinner
├── data/
│   └── wordlists/common.txt   # 200-path gobuster wordlist
├── cli.py           # Typer entry point
├── config.py        # Pydantic settings
└── constants.py     # Colors, profiles, tool binaries, paths
```

---

## Configuration

Config file: `~/.hexmind/config.toml` (auto-created on first run)

Key settings:

```toml
[ai]
model    = "mistral"
base_url = "http://localhost:11434"

[reports]
output_dir = "~/hexmind-reports"

[scan]
default_profile = "standard"
```

---

## Legal Notice

**Only scan systems you own or have explicit written permission to test.**

HexMind is designed for authorized security testing, CTF competitions, and
educational use only. Unauthorized scanning may violate the Computer Fraud
and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your
jurisdiction. The authors accept no liability for misuse.

---

## Roadmap

| Version | Stage | Description |
|---------|-------|-------------|
| 0.1.0 | Alpha | Core scaffold, DB layer, all runners, AI engine, reports ← **current** |
| 0.2.0 | Beta | Nuclei integration, custom plugin runner, rate-limit profiles |
| 0.3.0 | RC | Web UI (FastAPI + htmx), team workspace, shared findings DB |
| 1.0.0 | Stable | Production-ready release, installer, docs site |
| 2.0.0 | Stable | Batch scanning, CI/CD integration, findings API |
| 3.0.0 | Stable | Scheduling, team features, cloud-optional AI fallback |
