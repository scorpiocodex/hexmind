"""Global constants, enums, and configuration defaults for HexMind."""

from pathlib import Path

HEXMIND_VERSION: str = "1.0.0"

HEXMIND_DIR: Path = Path.home() / ".hexmind"
DB_PATH: Path = HEXMIND_DIR / "hexmind.db"
CONFIG_PATH: Path = HEXMIND_DIR / "config.toml"
REPORTS_DIR: Path = Path.home() / "hexmind-reports"
LOGS_DIR: Path = HEXMIND_DIR / "logs"
WORDLIST_PATH: Path = Path(__file__).parent / "data" / "wordlists" / "common.txt"

SPINNER_FRAMES: list[str] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# Rich markup color constants
COLOR_GREEN: str = "[bold #00ff9f]"
COLOR_CYAN: str = "[bold #00b4d8]"
COLOR_RED: str = "[bold #ff4444]"
COLOR_ORANGE: str = "[bold #ff8c00]"
COLOR_YELLOW: str = "[bold #ffd700]"
COLOR_SOFT_GREEN: str = "[#4ade80]"
COLOR_SLATE: str = "[#94a3b8]"
COLOR_DIM: str = "[dim #334155]"
COLOR_WHITE: str = "[#e2e8f0]"
COLOR_PURPLE: str = "[bold #a78bfa]"

# Tool binary names (overridable via config)
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
    "nmap": 600,
    "whois": 30,
    "whatweb": 60,
    "nikto": 900,
    "dig": 30,
    "curl": 30,
    "gobuster": 600,
    "sslscan": 60,
}

# Scan profile configurations
SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "tools": ["whois", "dig", "nmap"],
        "nmap_flags": ["-T4", "-F", "--open"],
        "nikto": False,
        "gobuster": False,
        "ai_passes": 1,
    },
    "standard": {
        "tools": ["whois", "dig", "curl", "nmap", "whatweb", "sslscan", "nikto"],
        "nmap_flags": ["-T3", "-sV", "-sC", "-O", "--open", "-p-"],
        "nikto": True,
        "nikto_mode": "light",
        "gobuster": False,
        "ai_passes": 2,
    },
    "deep": {
        "tools": ["whois", "dig", "curl", "nmap", "whatweb", "sslscan", "nikto", "gobuster"],
        "nmap_flags": ["-T2", "-sV", "-sC", "-O", "-A", "--open", "-p-", "--script", "vuln"],
        "nikto": True,
        "nikto_mode": "full",
        "gobuster": True,
        "ai_passes": 3,
    },
    "stealth": {
        "tools": ["whois", "dig", "curl", "nmap", "whatweb", "sslscan", "nikto"],
        "nmap_flags": ["-T1", "-sS", "-sV", "--open", "-p-"],
        "nikto": True,
        "nikto_mode": "light",
        "gobuster": False,
        "ai_passes": 2,
    },
}
