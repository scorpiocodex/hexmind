# HexMind — AI Penetration Testing Assistant
## Complete System Design Document v1.0

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Directory Structure](#3-directory-structure)
4. [Database Design](#4-database-design)
5. [Module Breakdown](#5-module-breakdown)
6. [Agentic Loop Design](#6-agentic-loop-design)
7. [CLI UX Design](#7-cli-ux-design)
8. [Recon Tool Pipeline](#8-recon-tool-pipeline)
9. [AI Analysis Engine](#9-ai-analysis-engine)
10. [Web Search & CVE Integration](#10-web-search--cve-integration)
11. [Report Export System](#11-report-export-system)
12. [Data Flow Diagrams](#12-data-flow-diagrams)
13. [Configuration & Settings](#13-configuration--settings)
14. [Dependency Map](#14-dependency-map)

---

## 1. Project Overview

**HexMind** is a fully local, offline-capable AI-powered penetration testing assistant. It orchestrates industry-standard recon tools, feeds their output to a locally running LLM (via Ollama/Mistral), and conducts multi-pass vulnerability analysis through an agentic loop. All findings are persisted in a SQLite database with full scan history and exportable reports.

### Design Principles
- **Zero cloud dependency** — all AI inference runs locally via Ollama
- **Tool composability** — each recon tool is a standalone, swappable module
- **Agentic by design** — the AI can request additional tool runs mid-analysis
- **History-first** — every scan, finding, and AI response is versioned and queryable
- **Operator safety** — built-in target validation, scope locking, and rate-limit guards

### Tech Stack
| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| AI Runtime | Ollama (mistral:latest) |
| Database | SQLite 3 + SQLAlchemy ORM |
| CLI Framework | Rich + Typer |
| HTTP Client | httpx (async) |
| Recon Tools | nmap, whois, whatweb, nikto, dig, curl, gobuster, sslscan |
| CVE Data | NVD API (free, no key for basic), cve.circl.lu |
| Web Search | DuckDuckGo Instant Answer API (free, no key) |
| Reports | Jinja2 templates → Markdown, HTML, PDF (via weasyprint) |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          HexMind CLI Entry Point                         │
│                          hexmind/cli.py (Typer)                          │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
              ┌─────────────────▼──────────────────┐
              │         Session Manager             │
              │   hexmind/core/session.py           │
              │  • Creates scan sessions            │
              │  • Manages target scope             │
              │  • Coordinates all modules          │
              └──────┬──────────┬──────────┬───────┘
                     │          │          │
          ┌──────────▼──┐  ┌────▼──────┐  ┌▼────────────────┐
          │  Recon       │  │  AI       │  │  Database        │
          │  Orchestrator│  │  Engine   │  │  Layer           │
          │  (async)     │  │  (Ollama) │  │  (SQLAlchemy)    │
          └──────┬───────┘  └────┬──────┘  └─────────────────┘
                 │               │
    ┌────────────▼──────┐  ┌─────▼──────────────────────────┐
    │  Tool Runners     │  │  Agentic Loop Controller        │
    │  • nmap_runner    │  │  • Parse AI tool requests       │
    │  • whois_runner   │  │  • Dispatch follow-up scans     │
    │  • nikto_runner   │  │  • Re-feed results to AI        │
    │  • dig_runner     │  │  • Convergence detection        │
    │  • curl_runner    │  └────────────────────────────────┘
    │  • whatweb_runner │
    │  • ssl_runner     │
    │  • gobuster_runner│
    └────────────┬──────┘
                 │
    ┌────────────▼──────────────────┐
    │  External Tool Processes      │
    │  (subprocess + asyncio)       │
    │  Real system binaries         │
    └───────────────────────────────┘
```

---

## 3. Directory Structure

```
hexmind/
│
├── cli.py                        # Typer CLI entry point
├── config.py                     # Global config, settings loader
├── constants.py                  # Enums, tool paths, prompt templates
│
├── core/
│   ├── session.py                # ScanSession orchestrator
│   ├── agentic_loop.py           # AI ↔ Tool feedback loop
│   ├── target_validator.py       # IP/domain validation, scope checks
│   └── rate_limiter.py           # Per-tool rate limiting
│
├── recon/
│   ├── __init__.py
│   ├── base_runner.py            # Abstract runner base class
│   ├── nmap_runner.py
│   ├── whois_runner.py
│   ├── nikto_runner.py
│   ├── dig_runner.py
│   ├── curl_runner.py
│   ├── whatweb_runner.py
│   ├── ssl_runner.py             # sslscan / openssl
│   ├── gobuster_runner.py
│   └── orchestrator.py           # Async tool pipeline coordinator
│
├── ai/
│   ├── engine.py                 # Ollama API client wrapper
│   ├── prompts.py                # All prompt templates
│   ├── parser.py                 # AI response parser (tool calls, findings)
│   └── context_builder.py        # Assembles recon data → AI context
│
├── search/
│   ├── duckduckgo.py             # DDG Instant Answer scraper
│   └── cve_lookup.py             # NVD + circl.lu CVE queries
│
├── db/
│   ├── models.py                 # SQLAlchemy ORM models (5 tables)
│   ├── database.py               # Engine, session factory
│   ├── repository.py             # CRUD operations
│   └── migrations.py             # Schema init / upgrades
│
├── reports/
│   ├── exporter.py               # Report generation orchestrator
│   ├── templates/
│   │   ├── report.md.j2          # Markdown template
│   │   ├── report.html.j2        # HTML template
│   │   └── report.pdf.j2         # PDF-ready HTML template
│   └── pdf_renderer.py           # weasyprint wrapper
│
├── ui/
│   ├── console.py                # Rich console singleton
│   ├── panels.py                 # Styled Rich panels/tables
│   ├── spinner.py                # Themed progress indicators
│   └── banner.py                 # ASCII art + startup display
│
└── data/
    ├── hexmind.db                # SQLite database (auto-created)
    ├── wordlists/                # Gobuster wordlists
    └── logs/                     # Raw tool stdout/stderr logs
```

---

## 4. Database Design

Five linked tables covering the full audit trail.

### 4.1 Entity Relationship Diagram

```
┌──────────────────┐       ┌──────────────────────┐
│   targets        │       │   scans              │
│──────────────────│       │──────────────────────│
│ id (PK)          │◄──────│ id (PK)              │
│ value            │       │ target_id (FK)        │
│ type             │       │ status               │
│ first_seen_at    │       │ started_at           │
│ last_seen_at     │       │ finished_at          │
│ tags             │       │ scan_profile         │
└──────────────────┘       │ tool_flags (JSON)    │
                           └──────────┬───────────┘
                                      │
              ┌───────────────────────┼────────────────────────┐
              │                       │                        │
   ┌──────────▼──────────┐  ┌────────▼──────────┐  ┌─────────▼──────────┐
   │  tool_results        │  │  findings         │  │  ai_conversations  │
   │─────────────────────│  │──────────────────│  │────────────────────│
   │ id (PK)              │  │ id (PK)           │  │ id (PK)            │
   │ scan_id (FK)         │  │ scan_id (FK)      │  │ scan_id (FK)       │
   │ tool_name            │  │ severity          │  │ role               │
   │ command_run          │  │ category          │  │ content            │
   │ raw_output           │  │ title             │  │ token_count        │
   │ parsed_output (JSON) │  │ description       │  │ created_at         │
   │ exit_code            │  │ affected_component│  │ loop_iteration     │
   │ duration_ms          │  │ cve_ids (JSON)    │  └────────────────────┘
   │ started_at           │  │ exploit_notes     │
   │ tool_version         │  │ remediation       │
   └─────────────────────┘  │ references (JSON) │
                             │ confidence_score  │
                             │ created_at        │
                             └──────────────────┘
```

### 4.2 Table Definitions

#### `targets`
```sql
CREATE TABLE targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    value       TEXT NOT NULL UNIQUE,          -- IP or domain
    type        TEXT NOT NULL,                 -- 'ip' | 'domain' | 'cidr'
    first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen   DATETIME,
    tags        TEXT,                          -- JSON array of strings
    notes       TEXT
);
```

#### `scans`
```sql
CREATE TABLE scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL REFERENCES targets(id),
    status       TEXT DEFAULT 'pending',       -- pending|running|done|failed
    started_at   DATETIME,
    finished_at  DATETIME,
    scan_profile TEXT DEFAULT 'standard',      -- quick|standard|deep|stealth
    tool_flags   TEXT,                         -- JSON: per-tool override flags
    error_log    TEXT
);
```

#### `tool_results`
```sql
CREATE TABLE tool_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id),
    tool_name      TEXT NOT NULL,
    command_run    TEXT NOT NULL,              -- exact shell command
    raw_output     TEXT,
    parsed_output  TEXT,                       -- JSON structured data
    exit_code      INTEGER,
    duration_ms    INTEGER,
    started_at     DATETIME,
    tool_version   TEXT
);
```

#### `findings`
```sql
CREATE TABLE findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER NOT NULL REFERENCES scans(id),
    severity           TEXT NOT NULL,          -- critical|high|medium|low|info
    category           TEXT,                   -- recon|vuln|misconfig|exposure
    title              TEXT NOT NULL,
    description        TEXT,
    affected_component TEXT,
    cve_ids            TEXT,                   -- JSON array
    exploit_notes      TEXT,
    remediation        TEXT,
    references         TEXT,                   -- JSON array of URLs
    confidence_score   REAL DEFAULT 0.0,       -- 0.0–1.0
    false_positive     BOOLEAN DEFAULT FALSE,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### `ai_conversations`
```sql
CREATE TABLE ai_conversations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id),
    role           TEXT NOT NULL,              -- 'user' | 'assistant'
    content        TEXT NOT NULL,
    token_count    INTEGER,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    loop_iteration INTEGER DEFAULT 0           -- agentic loop pass number
);
```

---

## 5. Module Breakdown

### 5.1 `cli.py` — Entry Point

Commands exposed via Typer:

| Command | Description |
|---|---|
| `hexmind scan <target>` | Run a full scan on target IP/domain |
| `hexmind scan <target> --profile quick` | Quick scan (nmap -T4 + whois only) |
| `hexmind scan <target> --profile deep` | Full deep scan (all tools) |
| `hexmind scan <target> --profile stealth` | Slow, low-noise scan |
| `hexmind history` | List all past scans |
| `hexmind history <scan_id>` | View findings from a past scan |
| `hexmind report <scan_id> --format md` | Export report (md/html/pdf) |
| `hexmind targets` | List all known targets |
| `hexmind search <query>` | Run a standalone DDG/CVE search |
| `hexmind compare <id1> <id2>` | Diff two scans of same target |
| `hexmind config` | Show/edit config (model, tool paths, etc.) |

**Scan Profiles:**

| Profile | Tools | Nmap Speed | Nikto | Gobuster | AI Passes |
|---|---|---|---|---|---|
| `quick` | nmap, whois, dig | T4 | ✗ | ✗ | 1 |
| `standard` | all except gobuster | T3 | light | ✗ | 2 |
| `deep` | all tools | T2 | full | yes | 3+ |
| `stealth` | all tools | T1 | slow | slow | 2 |

---

### 5.2 `core/agentic_loop.py` — Agentic Loop Controller

The core intelligence orchestration module. Controls multi-pass AI analysis.

**Loop Phases:**

```
Phase 0: INITIALIZATION
  └─ Validate target, create DB session, display banner

Phase 1: BASELINE RECON
  └─ Run all tools in scan profile in parallel (asyncio)
  └─ Store raw outputs in tool_results table

Phase 2: INITIAL AI ANALYSIS (Loop Iteration 0)
  └─ Build context from all tool outputs
  └─ Send to Ollama/Mistral with analysis prompt
  └─ Parse AI response for:
      ├─ Structured findings → insert into findings table
      ├─ Tool requests → queue for Phase 3
      └─ Questions needing web search → queue for search

Phase 3: AGENTIC FOLLOW-UP
  └─ Execute any tool requests from AI (targeted nmap scans, specific ports)
  └─ Execute any CVE/web searches
  └─ Re-feed all new data to AI (Loop Iteration 1)
  └─ Repeat until:
      ├─ AI produces no new tool requests
      ├─ OR max_iterations reached (default: 5)
      └─ OR convergence detected (same findings twice)

Phase 4: FINAL SYNTHESIS
  └─ AI produces executive summary + remediation plan
  └─ All findings ranked by severity + confidence
  └─ Report generation prompt

Phase 5: OUTPUT
  └─ Display findings table in terminal
  └─ Save to DB
  └─ Prompt user for report export
```

---

### 5.3 `recon/base_runner.py` — Abstract Tool Runner

Every tool runner inherits from `BaseRunner`:

```python
class BaseRunner(ABC):
    name: str                          # Tool identifier
    binary: str                        # System binary name
    timeout: int = 300                 # Default timeout (seconds)
    
    @abstractmethod
    def build_command(self, target, flags) -> list[str]
    
    @abstractmethod  
    def parse_output(self, raw: str) -> dict
    
    async def run(self, target, flags={}) -> ToolResult:
        # Checks binary exists
        # Runs via asyncio.subprocess
        # Times out gracefully
        # Returns ToolResult dataclass
        
    def get_version(self) -> str
        # Runs tool --version and caches
```

### 5.4 Tool Runner Specifications

#### `nmap_runner.py`
- **Commands per profile:**
  - quick: `nmap -T4 -F --open {target}`
  - standard: `nmap -T3 -sV -sC -O --open -p- {target}`
  - deep: `nmap -T2 -sV -sC -O -A --open -p- --script vuln {target}`
  - stealth: `nmap -T1 -sS -sV --open -p- {target}`
- **Parser:** XML output (`-oX`) → structured port/service dict
- **Agentic support:** AI can request specific port deep-scans

#### `nikto_runner.py`
- **Command:** `nikto -h {target} -Format json -output {tmpfile}`
- **Parser:** JSON output → list of vulnerability findings
- **Note:** Long-running; progress shown via tail on output file

#### `gobuster_runner.py`
- **Command:** `gobuster dir -u http://{target} -w {wordlist} -o {tmpfile}`
- **Wordlist:** bundled `/data/wordlists/common.txt` (10k entries)
- **Parser:** Line-by-line status code + path extraction

#### `ssl_runner.py`
- **Command:** `sslscan --xml={tmpfile} {target}:443`
- **Parser:** XML → cipher suites, certificate info, protocol versions
- **Also runs:** `openssl s_client -connect {target}:443` for cert chain

#### `dig_runner.py`
- **Queries:**
  - `dig ANY {domain}` — all record types
  - `dig {domain} MX` — mail servers
  - `dig {domain} TXT` — SPF/DKIM/DMARC
  - `dig -x {ip}` — reverse lookup
- **Parser:** Regex extraction of record sections

#### `curl_runner.py`
- **Command:** `curl -sI -L --max-time 15 {target}`
- **Extracts:** Server header, X-Powered-By, security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Analysis:** Missing security headers flagged as findings

#### `whois_runner.py`
- **Command:** `whois {target}`
- **Parser:** Regex extraction of registrar, creation date, nameservers, abuse contacts
- **Also:** `whois {ip}` for ASN/netblock info

#### `whatweb_runner.py`
- **Command:** `whatweb --log-json={tmpfile} {target}`
- **Parser:** JSON → detected technologies, versions, plugins

---

## 6. Agentic Loop Design

### AI Tool Call Protocol

The AI communicates tool requests using a structured XML-like syntax within its response. The parser extracts these and dispatches real tool runs.

**AI can emit:**
```
<tool_request>
  <tool>nmap</tool>
  <args>-sV -p 3306,5432,27017 {target}</args>
  <reason>Detected potential database services; need version info</reason>
</tool_request>

<search_request>
  <query>CVE Apache 2.4.49 path traversal exploit</query>
</search_request>

<cve_lookup>
  <cve_id>CVE-2021-41773</cve_id>
</cve_lookup>
```

### Convergence Detection

The loop terminates early when:
1. AI emits no `<tool_request>` or `<search_request>` blocks
2. Cosine similarity between consecutive AI responses exceeds 0.92
3. `max_iterations` config reached (default 5)
4. Same tool+args combination requested twice

### Context Window Management

Since Mistral has a limited context window (~32k tokens), context is managed via:
- **Truncation:** Raw tool outputs truncated to first N lines + last N lines
- **Summarization:** Previous AI iterations summarized before next pass
- **Priority ordering:** Critical findings kept, verbose nmap output compressed

---

## 7. CLI UX Design

### Color Scheme (Rich theme)
```
Background:        #0a0e1a  (deep navy-black)
Primary text:      #e2e8f0  (cool white)
Accent primary:    #00ff9f  (matrix green)
Accent secondary:  #00b4d8  (electric cyan)
Critical:          #ff4444  (alert red)
High:              #ff8c00  (amber)
Medium:            #ffd700  (yellow)
Low:               #4ade80  (soft green)
Info:              #94a3b8  (muted slate)
Border:            #1e3a5f  (deep blue)
Muted:             #334155  (dark slate)
```

### Typography (ASCII)
- **Banner:** Custom figlet-style HexMind logo
- **Section headers:** Box-drawing characters with colored borders
- **Progress:** Animated spinners with custom frames
- **Tables:** Rich Table with rounded corners, colored severity cells

### Panel Layout During Scan

```
╔══════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗███████╗██╗  ██╗███╗   ███╗██╗███╗   ██╗██████╗       ║
║  ██║  ██║██╔════╝╚██╗██╔╝████╗ ████║██║████╗  ██║██╔══██╗      ║
║  ███████║█████╗   ╚███╔╝ ██╔████╔██║██║██╔██╗ ██║██║  ██║      ║
║  ██╔══██║██╔══╝   ██╔██╗ ██║╚██╔╝██║██║██║╚██╗██║██║  ██║      ║
║  ██║  ██║███████╗██╔╝ ██╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝      ║
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝       ║
║                AI Penetration Testing Assistant v1.0             ║
╚══════════════════════════════════════════════════════════════════╝

  Target  ›  192.168.1.100        Profile  ›  STANDARD
  Scan ID ›  #0042                Status   ›  ● RUNNING
  Session ›  2024-01-15 14:23:01  Model    ›  mistral:latest

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [ PHASE 1 — RECON PIPELINE ]

  ✓  whois          →  2.1s    registrar: GoDaddy, created: 2019-03
  ✓  dig            →  0.4s    A: 192.168.1.100, MX: mail.target.com
  ⠦  nmap           →  45s     scanning 65535 ports...
  ◌  whatweb        →  waiting
  ◌  nikto          →  waiting
  ◌  curl_headers   →  waiting
  ◌  sslscan        →  waiting

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [ PHASE 2 — AI ANALYSIS (Pass 1/3) ]

  ⠧  Feeding 14,823 tokens to mistral:latest...
  ⠧  Model thinking...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Findings Display Table
```
  FINDINGS — 192.168.1.100  (Scan #0042)
  ──────────────────────────────────────────────────────────────────────
   #   SEVERITY    CATEGORY      FINDING                   CONFIDENCE
  ──────────────────────────────────────────────────────────────────────
   1   [CRITICAL]  Vulnerability  Apache 2.4.49 RCE (CVE-2021-41773)  94%
   2   [HIGH]      Misconfiguration  SSH weak ciphers (3DES, arcfour)  89%
   3   [HIGH]      Exposure       MySQL 5.7 exposed on 0.0.0.0:3306    91%
   4   [MEDIUM]    Security       Missing HSTS header                   99%
   5   [MEDIUM]    Security       Missing CSP header                    99%
   6   [LOW]       Info Disclosure  PHP 7.2.5 version in X-Powered-By  97%
   7   [INFO]      Recon          WordPress 5.8 detected (whatweb)      99%
  ──────────────────────────────────────────────────────────────────────
  Total: 1 Critical  2 High  2 Medium  1 Low  1 Info
```

---

## 8. Recon Tool Pipeline

### Async Execution Model

Tools run concurrently using `asyncio.gather()` with dependency ordering:

```
Tier 1 (parallel, immediate):
  whois, dig, curl_headers

Tier 2 (parallel, after Tier 1):
  nmap (long-running), whatweb, sslscan

Tier 3 (parallel, after nmap completes):
  nikto (needs open ports), gobuster (if web detected)

Tier 4 (agentic, AI-requested):
  Any tool with AI-specified custom arguments
```

### Tool Output Normalization

Each runner returns a `ToolResult` dataclass:
```python
@dataclass
class ToolResult:
    tool_name: str
    command_run: str
    raw_output: str
    parsed_output: dict          # Structured, tool-specific
    exit_code: int
    duration_ms: int
    error: Optional[str]
    metadata: dict               # version, flags used, etc.
```

---

## 9. AI Analysis Engine

### Prompt Architecture

**System Prompt (constant):**
```
You are HexMind, an expert penetration tester and security analyst with 20 years
of experience. You analyze reconnaissance data and identify vulnerabilities with
precision. Always respond with structured findings in the specified format.
Be specific, cite CVE IDs where applicable, and suggest realistic exploits
and remediations. You may request additional tool runs using <tool_request> tags.
```

**Analysis Prompt (per iteration):**
```
TARGET: {target}
SCAN PROFILE: {profile}
ITERATION: {n} of {max}

=== TOOL RESULTS ===
{formatted_tool_outputs}

=== PREVIOUS FINDINGS (if iteration > 0) ===
{previous_findings_summary}

=== TASK ===
1. Analyze all tool outputs for security vulnerabilities
2. For each finding, specify: severity, category, CVE IDs (if any), exploit notes, remediation
3. Identify any gaps in data that require additional tool runs (use <tool_request> tags)
4. Identify any CVEs or exploits to search for (use <search_request> tags)
5. On the final iteration, produce an executive summary and risk rating (0-100)

Format findings as:
<finding>
  <severity>CRITICAL|HIGH|MEDIUM|LOW|INFO</severity>
  <category>vulnerability|misconfiguration|exposure|recon</category>
  <title>Short title</title>
  <description>Detailed description</description>
  <component>Affected service/component</component>
  <cves>CVE-XXXX-XXXXX, ...</cves>
  <exploit>How this could be exploited</exploit>
  <remediation>How to fix this</remediation>
  <confidence>0.0-1.0</confidence>
</finding>
```

### Ollama API Integration

```python
class OllamaEngine:
    base_url: str = "http://localhost:11434"
    model: str = "mistral:latest"
    
    async def generate(self, messages, stream=True) -> AsyncIterator[str]:
        # POST /api/chat
        # stream=True → token-by-token display in terminal
        
    async def check_model_available(self) -> bool:
        # GET /api/tags → check mistral:latest is pulled
        
    def estimate_tokens(self, text: str) -> int:
        # ~4 chars per token approximation
```

---

## 10. Web Search & CVE Integration

### DuckDuckGo Search (`search/duckduckgo.py`)

- **API:** `https://api.duckduckgo.com/?q={query}&format=json&no_html=1`
- **No API key required**
- **Rate limiting:** 1 request/2 seconds (built-in)
- **Fallback:** HTML scrape of `https://html.duckduckgo.com/html/?q={query}`
- **Output:** Top 5 results (title, URL, snippet) stored in DB

### CVE Lookup (`search/cve_lookup.py`)

**Source 1 — CIRCL CVE API (no key needed):**
- `https://cve.circl.lu/api/cve/{CVE_ID}` — single CVE details
- `https://cve.circl.lu/api/search/{vendor}/{product}` — product search
- Returns: CVSS score, description, references, exploit availability

**Source 2 — NVD API (free tier, no key):**
- `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}`
- Rate limit: 5 requests per 30 seconds (respected by rate_limiter.py)

**Source 3 — Exploit-DB search (scraper):**
- `https://www.exploit-db.com/search?cve={CVE_ID}`
- Checks if public exploits exist for found CVEs

---

## 11. Report Export System

### Export Formats

| Format | Tool | Output |
|---|---|---|
| Markdown | Jinja2 | `report_scan_42_20240115.md` |
| HTML | Jinja2 + inline CSS | `report_scan_42_20240115.html` |
| PDF | Jinja2 → weasyprint | `report_scan_42_20240115.pdf` |
| JSON | direct DB export | `report_scan_42_20240115.json` |

### Report Sections

1. **Cover Page** — Target, scan date, scan ID, profile, risk score (0-100)
2. **Executive Summary** — AI-generated paragraph summary
3. **Risk Score Breakdown** — Severity counts, risk matrix visualization (ASCII/SVG)
4. **Findings (by severity)** — Full finding cards with CVE links, exploit notes, remediation
5. **Tool Output Summary** — Key data from each recon tool
6. **AI Conversation Log** — Full agentic loop transcript
7. **Remediation Roadmap** — Prioritized fix list
8. **Appendix** — Raw tool outputs, scan configuration

---

## 12. Data Flow Diagrams

### Full Scan Data Flow

```
User: hexmind scan 192.168.1.100 --profile standard
         │
         ▼
  ┌─────────────────┐
  │ Target Validator│  → validates IP format, checks not localhost/RFC1918 private
  └────────┬────────┘    (with --allow-private flag override)
           │
           ▼
  ┌─────────────────┐
  │  DB: Create     │  → INSERT targets (if new) + INSERT scans (status=running)
  │  Session        │
  └────────┬────────┘
           │
           ▼
  ┌──────────────────────────────────────────────────┐
  │  ASYNC RECON PIPELINE                            │
  │                                                  │
  │  Tier1: [whois] [dig] [curl]  ←─ parallel       │
  │              ↓                                   │
  │  Tier2: [nmap] [whatweb] [ssl] ←─ parallel      │
  │              ↓ (nmap done)                       │
  │  Tier3: [nikto] (if port 80/443 open)            │
  │                                                  │
  │  Each result → INSERT tool_results               │
  └────────────────────┬─────────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────────┐
  │  CONTEXT BUILDER                                 │
  │  Formats all tool outputs into AI prompt         │
  │  Truncates to fit context window                 │
  │  ~14,000 tokens typical for standard scan        │
  └────────────────────┬─────────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────────┐
  │  OLLAMA / MISTRAL                                │
  │  Streams response token-by-token to terminal     │
  │  Full response saved → ai_conversations          │
  └────────────────────┬─────────────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────────────┐
  │  RESPONSE PARSER                                 │
  │  Extract <finding> blocks → INSERT findings      │
  │  Extract <tool_request> → queue new tool runs    │
  │  Extract <search_request> → queue web searches   │
  └────────────────────┬─────────────────────────────┘
                       │
              ┌────────┴────────┐
              │  Any requests?  │
              └────────┬────────┘
                       │
              Yes ◄────┤►── No → Phase 4 Final Synthesis
               │
               ▼
  ┌──────────────────────────────────────────────────┐
  │  AGENTIC FOLLOW-UP                               │
  │  Run requested tools/searches                    │
  │  Append results to context                       │
  │  Re-query Ollama (loop_iteration += 1)           │
  └──────────────────────────────────────────────────┘
```

---

## 13. Configuration & Settings

Config file: `~/.hexmind/config.toml`

```toml
[model]
ollama_url = "http://localhost:11434"
model_name = "mistral:latest"
max_tokens = 32000
temperature = 0.1
stream = true

[scan]
default_profile = "standard"
max_agentic_iterations = 5
tool_timeout_seconds = 300
allow_private_targets = false
parallel_tools = true

[tools]
nmap = "/usr/bin/nmap"
nikto = "/usr/bin/nikto"
whatweb = "/usr/bin/whatweb"
gobuster = "/usr/local/bin/gobuster"
sslscan = "/usr/bin/sslscan"

[database]
path = "~/.hexmind/hexmind.db"
max_raw_output_bytes = 1048576   # 1MB per tool result

[search]
duckduckgo_rate_limit_seconds = 2
nvd_rate_limit_seconds = 6
max_search_results = 5

[reports]
output_dir = "~/hexmind-reports"
default_format = "html"
include_raw_output = true

[ui]
color_scheme = "dark"
stream_ai_output = true
show_tool_commands = true
verbose = false
```

---

## 14. Dependency Map

### Python Packages
```
typer[all]          # CLI framework with Rich integration
rich                # Terminal UI (panels, tables, progress, colors)
sqlalchemy          # ORM for SQLite
httpx               # Async HTTP client (Ollama API + web search)
jinja2              # Report templating
weasyprint          # PDF generation from HTML
pydantic            # Data validation / settings
python-dotenv       # Environment variable loading
asyncio             # Async tool execution
xmltodict           # Parse nmap/sslscan XML output
```

### System Dependencies
```
nmap                # Port scanning + service detection
nikto               # Web vulnerability scanner
whatweb             # Web technology fingerprinter
gobuster            # Directory/DNS brute-forcing
sslscan             # SSL/TLS configuration analysis
whois               # Domain registration info
dig                 # DNS queries (dnsutils package)
curl                # HTTP header fetching
openssl             # SSL certificate inspection
ollama              # Local LLM runtime (mistral model)
```

### Optional / Enhancement
```
masscan             # Faster port scanning for large ranges
subfinder           # Subdomain enumeration
nuclei              # Template-based vulnerability scanner
amass               # Advanced DNS enumeration
```

---

## Appendix A: Scan Profile Quick Reference

| Feature | quick | standard | deep | stealth |
|---|---|---|---|---|
| Nmap timing | T4 | T3 | T2 | T1 |
| Nmap scripts | none | default | vuln+all | none |
| All ports | ✗ | ✓ | ✓ | ✓ |
| OS detect | ✗ | ✓ | ✓ | ✗ |
| Nikto | ✗ | light | full | light |
| Gobuster | ✗ | ✗ | ✓ | ✗ |
| SSL scan | ✗ | ✓ | ✓ | ✓ |
| AI passes | 1 | 2 | 3+ | 2 |
| Est. time | 2-5 min | 15-30 min | 60-120 min | 60-90 min |

---

*HexMind Design Document v1.0 — For design reference only*
*All tool usage must comply with applicable laws and authorization requirements*
