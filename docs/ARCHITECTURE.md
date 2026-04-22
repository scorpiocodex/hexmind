ARCHITECTURE.md
1. PROJECT OVERVIEW

HexMind is a fully local, CLI-based AI penetration testing assistant built with Python 3.11+. It orchestrates industry-standard reconnaissance tools, aggregates their outputs, and feeds them into a locally hosted LLM via Ollama to perform multi-pass vulnerability analysis. The system is designed around an agentic loop, enabling the AI to request additional scans dynamically based on findings.

The architecture emphasizes modularity, asynchronous execution, reproducibility, and full auditability. Every scan, tool execution, and AI interaction is persisted in a relational database, enabling historical comparison, reporting, and deterministic re-analysis.

2. TECH STACK TABLE
Python Dependencies
Name	Version	Install Command	Purpose
typer	==0.12.3	pip install typer==0.12.3	CLI framework
rich	==13.7.1	pip install rich==13.7.1	Terminal UI rendering
sqlalchemy	==2.0.30	pip install sqlalchemy==2.0.30	ORM
httpx	==0.27.0	pip install httpx==0.27.0	Async HTTP client
jinja2	==3.1.4	pip install jinja2==3.1.4	Templating
weasyprint	==62.3	pip install weasyprint==62.3	PDF generation
pydantic	==2.7.1	pip install pydantic==2.7.1	Validation
xmltodict	==0.13.0	pip install xmltodict==0.13.0	XML parsing
python-dotenv	==1.0.1	pip install python-dotenv==1.0.1	Env config
asyncio	stdlib	—	Async runtime
External Runtime
Name	Install Command	Purpose
ollama	curl https://ollama.ai/install.sh
 | sh	Local LLM runtime
System Binaries
Name	Install
nmap	sudo apt install nmap
whois	sudo apt install whois
whatweb	sudo apt install whatweb
nikto	sudo apt install nikto
dig	sudo apt install dnsutils
curl	sudo apt install curl
gobuster	sudo apt install gobuster
sslscan	sudo apt install sslscan
3. COMPLETE DIRECTORY TREE
hexmind/
├── cli.py                    # CLI entry
├── config.py                # Config loader
├── constants.py             # Constants and enums
├── __init__.py

├── core/
│   ├── __init__.py
│   ├── session.py           # Scan session orchestrator
│   ├── agentic_loop.py      # Agent loop controller
│   ├── target_validator.py  # Input validation
│   └── rate_limiter.py      # Rate limiting

├── recon/
│   ├── __init__.py
│   ├── base_runner.py       # Abstract runner
│   ├── orchestrator.py      # Async pipeline
│   ├── nmap_runner.py
│   ├── whois_runner.py
│   ├── nikto_runner.py
│   ├── dig_runner.py
│   ├── curl_runner.py
│   ├── whatweb_runner.py
│   ├── ssl_runner.py
│   └── gobuster_runner.py

├── ai/
│   ├── __init__.py
│   ├── engine.py            # Ollama client
│   ├── prompts.py           # Prompt templates
│   ├── parser.py            # AI output parser
│   └── context_builder.py   # Context assembly

├── search/
│   ├── __init__.py
│   ├── duckduckgo.py
│   └── cve_lookup.py

├── db/
│   ├── __init__.py
│   ├── models.py
│   ├── database.py
│   ├── repository.py
│   └── migrations.py

├── reports/
│   ├── __init__.py
│   ├── exporter.py
│   ├── pdf_renderer.py
│   └── templates/
│       ├── report.md.j2
│       ├── report.html.j2
│       └── report.pdf.j2

├── ui/
│   ├── __init__.py
│   ├── console.py
│   ├── panels.py
│   ├── spinner.py
│   └── banner.py

└── data/
    ├── hexmind.db
    ├── logs/
    └── wordlists/
4. MODULE INTERFACE CONTRACTS
core/session.py
class ScanSession:
    def __init__(self, target: str, profile: str) -> None

    async def run(self) -> None
    def finalize(self) -> None
core/agentic_loop.py
class AgenticLoop:
    def __init__(self, scan_id: int) -> None

    async def execute(self) -> None
    async def run_iteration(self, iteration: int) -> dict
recon/base_runner.py
class BaseRunner(ABC):
    def __init__(self) -> None

    async def run(self, target: str, flags: dict) -> ToolResult
    def build_command(self, target: str, flags: dict) -> list[str]
    def parse_output(self, raw: str) -> dict
recon/orchestrator.py
class ReconOrchestrator:
    def __init__(self) -> None

    async def run_all(self, target: str, profile: str) -> list[ToolResult]
ai/engine.py
class AIEngine:
    def __init__(self, base_url: str, model: str) -> None

    async def generate(self, prompt: str) -> str
ai/parser.py
class AIParser:
    def parse(self, response: str) -> dict
db/models.py
class Target(Base): ...
class Scan(Base): ...
class ToolResult(Base): ...
class Finding(Base): ...
class AIConversation(Base): ...
5. DATABASE SCHEMA
SQL DDL
CREATE TABLE targets (
 id INTEGER PRIMARY KEY,
 value TEXT UNIQUE,
 type TEXT,
 first_seen DATETIME,
 last_seen DATETIME
);

CREATE TABLE scans (
 id INTEGER PRIMARY KEY,
 target_id INTEGER,
 status TEXT,
 started_at DATETIME,
 finished_at DATETIME,
 FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE tool_results (
 id INTEGER PRIMARY KEY,
 scan_id INTEGER,
 tool_name TEXT,
 raw_output TEXT,
 FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE findings (
 id INTEGER PRIMARY KEY,
 scan_id INTEGER,
 severity TEXT,
 title TEXT,
 FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE ai_conversations (
 id INTEGER PRIMARY KEY,
 scan_id INTEGER,
 role TEXT,
 content TEXT,
 FOREIGN KEY(scan_id) REFERENCES scans(id)
);
6. ASYNC EXECUTION MODEL
Async Functions
ReconOrchestrator.run_all → async
BaseRunner.run → async
AgenticLoop.execute → async
AIEngine.generate → async
Execution Tiers
Tier 1: whois, dig, curl
Tier 2: nmap, whatweb, sslscan
Tier 3: nikto, gobuster
Tier 4: AI-triggered
Subprocess Strategy
asyncio.create_subprocess_exec
stdout/stderr pipes
timeout via asyncio.wait_for
7. AGENTIC LOOP STATE MACHINE
States

INIT → RECON → ANALYZE → FOLLOWUP → FINAL → DONE

Convergence Detection
if similarity(prev, current) > 0.92:
    stop
Context Management
Keep latest findings
Truncate raw outputs
Summarize history
Limits
max_iterations = 5
8. OLLAMA API CONTRACT
Request
POST /api/generate
{
 "model": "mistral",
 "prompt": "...",
 "stream": true
}
Streaming
async for chunk in response:
    buffer += chunk
Errors
404 → model missing
timeout → retry
OOM → reduce context
9. PROMPT TEMPLATES
System Prompt
You are HexMind, an expert penetration tester...
Analysis Prompt
TARGET: {target}
RESULTS:
{tool_outputs}
Final Prompt
Provide executive summary and remediation.
10. CLI COMMAND REGISTRY
@app.command()
def scan(target: str, profile: str = "standard"): ...

@app.command()
def history(): ...

@app.command()
def report(scan_id: int, format: str = "md"): ...

Examples:

hexmind scan example.com
hexmind report 1 --format pdf
11. BUILD ORDER / PHASE PLAN
Config + constants
DB layer
CLI skeleton
Recon runners
Async orchestrator
AI engine
Agentic loop
Reports
12. CONFIGURATION SCHEMA
[ai]
model = "mistral"
base_url = "http://localhost:11434"

[scan]
max_iterations = 5
timeout = 300

[db]
path = "data/hexmind.db"
13. ERROR TAXONOMY
class HexMindError(Exception): ...
class ToolExecutionError(HexMindError): ...
class AIError(HexMindError): ...
class DatabaseError(HexMindError): ...
class ValidationError(HexMindError): ...

Ownership:

core → ValidationError
recon → ToolExecutionError
ai → AIError
db → DatabaseError

END OF ARCHITECTURE.md