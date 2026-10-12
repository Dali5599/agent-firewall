from pathlib import Path
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Enterprise-grade configuration management for Agent Firewall.
    Loads and validates settings from environment variables and .env files.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Server Configuration
    host: str = Field(
        default="127.0.0.1",
        description="Host address for the Agent Firewall proxy server."
    )
    port: int = Field(
        default=8080,
        description="Port for the Agent Firewall proxy server."
    )
    debug: bool = Field(
        default=False,
        description="Enable debug logging and development mode."
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)."
    )

    # Database & Storage
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/agent_firewall.db",
        description="Sovereign SQLite WAL audit log database connection string."
    )
    data_dir: Path = Field(
        default=Path("./data"),
        description="Directory for local persistent storage."
    )

    # Security & Redaction
    redact_secrets: bool = Field(
        default=True,
        description="Enable real-time regex secret and PII redaction."
    )
    custom_redaction_patterns: List[str] = Field(
        default_factory=list,
        description="Additional custom regex patterns to redact from traffic."
    )

    # Circuit Breakers & Token Budgets
    token_budget_limit: int = Field(
        default=100000,
        description="Hard token budget limit per session/day before tripping the circuit breaker."
    )
    block_destructive_bash: bool = Field(
        default=True,
        description="Enable heuristic blocking of destructive bash commands in tool outputs/inputs."
    )

    # Upstream API Gateway Integrations
    openai_api_base: str = Field(
        default="https://api.openai.com/v1",
        description="Base URL for upstream OpenAI API routing."
    )
    anthropic_api_base: str = Field(
        default="https://api.anthropic.com",
        description="Base URL for upstream Anthropic API routing."
    )
    master_api_key: Optional[str] = Field(
        default=None,
        description="Master API key required by clients to authenticate against the firewall proxy."
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validates that the log level is a standard Python logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Invalid log_level: {v}. Must be one of {valid_levels}")
        return upper_v

    @field_validator("data_dir", mode="before")
    @classmethod
    def ensure_data_dir(cls, v: Any) -> Path:
        """Ensures the data directory exists on disk."""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path


def get_settings() -> Settings:
    """
    Factory function to instantiate and cache application settings.
    Returns:
        Settings: Validated configuration object.
    """
    return Settings()
