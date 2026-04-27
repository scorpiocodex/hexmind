"""Global constants, enums, and configuration defaults for HexMind."""

from pathlib import Path

HEXMIND_VERSION: str = "0.1.0"
HEXMIND_CODENAME: str = "alpha"

VERSION_ROADMAP: dict[str, str] = {
    "0.1.0": "Alpha — 8 runners, agentic AI loop, reports, CVE search",
    "0.2.0": "Beta — nuclei, subfinder, batch scanning, plugin system",
    "0.3.0": "RC — full test suite, performance tuning, hardening",
    "1.0.0": "Stable Release 1 — production ready, pip installable",
    "2.0.0": "Stable Release 2 — REST API, team features, scheduling",
    "3.0.0": "Stable Release 3 — cloud sync, custom AI models, GUI",
}

# Filesystem paths
HEXMIND_DIR: Path = Path("~/.hexmind").expanduser()
DB_PATH: Path = HEXMIND_DIR / "hexmind.db"
CONFIG_PATH: Path = HEXMIND_DIR / "config.toml"
REPORTS_DIR: Path = Path("~/hexmind-reports").expanduser()
LOGS_DIR: Path = HEXMIND_DIR / "logs"

WORDLIST_PATH: Path = Path(__file__).parent / "data" / "wordlists" / "common.txt"

# Rich color names (used in Theme definitions and style= arguments)
COLOR_GREEN: str = "bright_green"
COLOR_CYAN: str = "cyan"
COLOR_RED: str = "bright_red"
COLOR_ORANGE: str = "dark_orange"
COLOR_YELLOW: str = "yellow"
COLOR_SOFT_GREEN: str = "green"
COLOR_SLATE: str = "bright_black"
COLOR_DIM: str = "dim"
COLOR_WHITE: str = "bright_white"
COLOR_PURPLE: str = "medium_purple"
COLOR_BORDER: str = "steel_blue"

# Severity → Rich color mapping (used by panels.py and CLI output)
SEVERITY_COLORS: dict[str, str] = {
    "critical": COLOR_RED,
    "high": COLOR_ORANGE,
    "medium": COLOR_YELLOW,
    "low": COLOR_SOFT_GREEN,
    "info": COLOR_SLATE,
}

# Severity → sort rank (lower = more critical)
SEVERITY_RANKS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Severity → risk score weights (used by _finalize_scan)
RISK_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high":     20,
    "medium":   10,
    "low":       3,
    "info":      0,
}

# Tool binary names (keys match runner .name attributes)
TOOL_BINARIES: dict[str, str] = {
    "nmap": "nmap",
    "whois": "whois",
    "whatweb": "whatweb",
    "nikto": "nikto",
    "dig": "dig",
    "curl": "curl",
    "gobuster": "gobuster",
    "sslscan": "sslscan",
}

# Per-tool default timeouts in seconds
TOOL_TIMEOUTS: dict[str, int] = {
    "nmap":     1800,   # 30 min max — covers deep -p- scan
    "whois":    30,
    "whatweb":  60,
    "nikto":    300,
    "dig":      15,
    "curl":     30,
    "gobuster": 300,
    "sslscan":  60,
}

# Scan profile configurations
SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "nmap_flags": ["-T4", "-F", "--open"],
        "nikto_mode": None,
        "run_gobuster": False,
        "run_ssl": False,
        "ai_passes": 1,
        "description": "Fast scan: whois, dig, curl, nmap -F, whatweb",
        "est_minutes": "2–5",
    },
    "standard": {
        # Top 1000 ports (nmap default, NO -p-)
        # Completes in 2-5 min vs 30+ min for -p-
        "nmap_flags": ["-T3", "-sV", "-sC", "--open"],
        "nikto_mode": "light",
        "run_gobuster": False,
        "run_ssl": True,
        "ai_passes": 2,
        "description": "Full scan: all tools except gobuster",
        "est_minutes": "10–20",
    },
    "deep": {
        "nmap_flags": ["-T3", "-sV", "-sC", "--open",
                       "-p-", "--script", "vuln,default"],
        "nikto_mode": "full",
        "run_gobuster": True,
        "run_ssl": True,
        "ai_passes": 3,
        "description": "Thorough scan: all tools + vuln scripts + gobuster",
        "est_minutes": "60–120",
    },
    "stealth": {
        # Top 1000 ports, slow timing — -sT works without root
        "nmap_flags": ["-T2", "-sT", "-sV", "--open"],
        "nikto_mode": "light",
        "run_gobuster": False,
        "run_ssl": True,
        "ai_passes": 2,
        "description": "Low-noise scan: slow timing, minimal footprint",
        "est_minutes": "30–60",
    },
}

# Async execution tiers (tool names in run order)
RECON_TIERS: list[list[str]] = [
    ["whois", "dig", "curl"],
    ["nmap", "whatweb", "sslscan"],
    ["nikto", "gobuster"],
]

# Spinner animation frames
SPINNER_FRAMES: list[str] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
