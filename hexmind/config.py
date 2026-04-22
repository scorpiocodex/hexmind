"""Global configuration loader and settings model for HexMind."""

from __future__ import annotations

import functools
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class HexMindConfig(BaseSettings):
    """Application-wide settings loaded from env vars and config.toml."""

    model_config = SettingsConfigDict(
        env_prefix="HEXMIND_",
        env_nested_delimiter="_",
        case_sensitive=False,
    )

    # AI settings
    ai_model: str = "mistral"
    ai_base_url: str = "http://localhost:11434"
    ai_temperature: float = 0.1
    ai_max_tokens: int = 4096
    ai_stream: bool = True

    # Scan settings
    scan_max_iterations: int = 5
    scan_timeout: int = 300
    scan_default_profile: str = "standard"
    scan_allow_private: bool = False

    # Database
    db_path: str = "~/.hexmind/hexmind.db"

    # Reports
    reports_output_dir: str = "~/hexmind-reports"
    reports_default_format: str = "html"

    # UI
    ui_verbose: bool = False


@functools.lru_cache(maxsize=1)
def get_config() -> HexMindConfig:
    """Return the cached singleton HexMindConfig instance."""
    raise NotImplementedError("TODO: implement")


def load_config(path: Path) -> HexMindConfig:
    """Load and return a HexMindConfig from the given TOML file path."""
    raise NotImplementedError("TODO: implement")
