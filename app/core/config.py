"""Application settings via pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ollama_host: str = "http://localhost:11434"
    ollama_decision_model: str = "nimble"
    ollama_timeout: float = 120.0
    jevshield_block_threshold: float = 0.85
    jevshield_review_threshold: float = 0.50
    fail_closed: bool = True
    jevshield_trust_user: bool = False
    jevshield_api_url: str = "http://127.0.0.1:8000"


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
