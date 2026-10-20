from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Email Forensics Platform"
    environment: str = "development"
    version: str = "0.1.0"
    database_path: str = "data/analyses.db"
    max_upload_bytes: int = 15 * 1024 * 1024
    max_batch_files: int = 20
    allowed_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="APP_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
