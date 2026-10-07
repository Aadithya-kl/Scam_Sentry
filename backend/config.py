"""Backend configuration, overridable through environment variables or a .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from ml.config import MODEL_FILE


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SCAMSENTRY_", extra="ignore")

    app_name: str = "ScamSentry AI"
    api_version: str = "1.0.0"

    # Path to the joblib pipeline produced by `python -m ml.train`.
    model_path: Path = MODEL_FILE

    # Comma-separated list of allowed browser origins for CORS.
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Decision threshold for the ML spam probability (see services/prediction_service.py)
    spam_threshold: float = 0.5

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
