"""Application configuration for the DomainVitals backend."""

from functools import lru_cache
from typing import Optional

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "DomainVitals"
    environment: str = Field(default="development")
    openai_api_key: Optional[SecretStr] = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o", alias="OPENAI_MODEL")
    shodan_api_key: Optional[SecretStr] = Field(default=None, alias="SHODAN_API_KEY")
    demo_mode: bool = Field(default=False, alias="DEMO_MODE")
    allowed_origins: str = Field(default="http://localhost:3000", alias="ALLOWED_ORIGINS")
    port: int = Field(default=8000, alias="PORT")
    request_timeout_seconds: float = Field(default=12.0, ge=1.0, le=60.0)
    max_report_findings: int = Field(default=40, ge=5, le=200)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached settings object for dependency injection."""

    return Settings()
