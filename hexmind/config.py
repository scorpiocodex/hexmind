"""Global configuration loader and settings model for HexMind."""

from __future__ import annotations

import functools
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from hexmind.constants import CONFIG_PATH, DB_PATH, REPORTS_DIR


class AIConfig(BaseModel):
    model: str = "mistral"
    base_url: str = "http://localhost:11434"
    temperature: float = Field(0.1, ge=0.0, le=1.0)
    max_tokens: int = Field(4096, ge=256, le=32768)
    stream: bool = True


class ScanConfig(BaseModel):
    max_iterations: int = Field(5, ge=1, le=20)
    timeout: int = Field(300, ge=30, le=3600)
    default_profile: str = "standard"
    allow_private: bool = False
    parallel_tools: bool = True

    @field_validator("default_profile")
    @classmethod
    def valid_profile(cls, v: str) -> str:
        allowed = {"quick", "standard", "deep", "stealth"}
        if v not in allowed:
            raise ValueError(f"profile must be one of {allowed}")
        return v


class DBConfig(BaseModel):
    path: str = str(DB_PATH)


class ToolsConfig(BaseModel):
    nmap: str = "nmap"
    whois: str = "whois"
    whatweb: str = "whatweb"
    nikto: str = "nikto"
    dig: str = "dig"
    curl: str = "curl"
    gobuster: str = "gobuster"
    sslscan: str = "sslscan"


class SearchConfig(BaseModel):
    ddg_rate_limit: float = Field(2.0, ge=0.5)
    nvd_rate_limit: float = Field(6.0, ge=1.0)
    max_results: int = Field(5, ge=1, le=20)


class ReportsConfig(BaseModel):
    output_dir: str = str(REPORTS_DIR)
    default_format: str = "html"
    include_raw: bool = True

    @field_validator("default_format")
    @classmethod
    def valid_format(cls, v: str) -> str:
        if v not in {"md", "html", "pdf", "json"}:
            raise ValueError("format must be md|html|pdf|json")
        return v


class UIConfig(BaseModel):
    stream_ai_output: bool = True
    show_commands: bool = True
    verbose: bool = False


class HexMindConfig(BaseModel):
    ai: AIConfig = Field(default_factory=AIConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    db: DBConfig = Field(default_factory=DBConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    search: SearchConfig = Field(default_factory=SearchConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    ui: UIConfig = Field(default_factory=UIConfig)

    @property
    def db_path(self) -> Path:
        return Path(self.db.path).expanduser().resolve()

    @property
    def reports_dir(self) -> Path:
        return Path(self.reports.output_dir).expanduser().resolve()


def _load_toml(path: Path) -> dict:
    """Load a TOML file and return its data. Returns {} if missing."""
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


@functools.lru_cache(maxsize=1)
def get_config() -> HexMindConfig:
    """Load config from ~/.hexmind/config.toml, falling back to project config.toml."""
    data = _load_toml(CONFIG_PATH)
    if not data:
        local = Path(__file__).parent.parent / "config.toml"
        data = _load_toml(local)
    return HexMindConfig.model_validate(data)


def reset_config_cache() -> None:
    """Clear the lru_cache so config reloads on next get_config() call."""
    get_config.cache_clear()


def _value_to_toml(val: object) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    else:
        return f'"{val}"'


def _dict_to_toml(data: dict) -> str:
    scalar_lines: list[str] = []
    section_blocks: list[str] = []

    for key, val in data.items():
        if isinstance(val, dict):
            inner = "\n".join(f"{k} = {_value_to_toml(v)}" for k, v in val.items())
            section_blocks.append(f"[{key}]\n{inner}")
        else:
            scalar_lines.append(f"{key} = {_value_to_toml(val)}")

    parts: list[str] = []
    if scalar_lines:
        parts.append("\n".join(scalar_lines))
    parts.extend(section_blocks)
    return "\n\n".join(parts)


def save_config(cfg: HexMindConfig, path: Path | None = None) -> None:
    """Serialize HexMindConfig to TOML and write to disk."""
    target = path or CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    toml_str = _dict_to_toml(cfg.model_dump())
    target.write_text(toml_str, encoding="utf-8")
