"""Central configuration management for the CCK platform."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CCKSettings(BaseSettings):
    """Platform settings loaded from environment variables with defaults."""

    environment: str = Field(
        default="development",
        description="Runtime environment name (development, testing, staging, production)",
    )
    sqlite_db_path: Path = Field(
        default=Path("./cck.db"),
        description="Path to local SQLite database file",
    )
    database_url: str = Field(
        default="sqlite+aiosqlite:///./cck.db",
        description="Async database connection string for local SQLite or remote PostgreSQL",
    )
    log_level: str = Field(
        default="INFO",
        description="Log verbosity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    api_host: str = Field(
        default="0.0.0.0",
        description="Host interface for CCK HTTP API",
    )
    api_port: int = Field(
        default=8000,
        description="Port for CCK HTTP API",
    )
    enable_tamper_evident_chain: bool = Field(
        default=True,
        description="Whether to cryptographically chain audit records via SHA-256",
    )
    default_risk_threshold: float = Field(
        default=0.75,
        description="Risk score above which actions require human approval if not blocked",
    )
    shadow_mode: bool = Field(
        default=False,
        description="When true, evaluates policies and logs violations but does not block execution",
    )

    model_config = SettingsConfigDict(
        env_prefix="CCK_",
        env_file=".env",
        extra="ignore",
    )


# Global settings singleton
_settings_instance: CCKSettings | None = None


def get_settings() -> CCKSettings:
    """Return the global configuration instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = CCKSettings()
    return _settings_instance
