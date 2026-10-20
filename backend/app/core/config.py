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

    enrichment_enabled: bool = True
    offline_mode: bool = False
    cache_path: str = "data/cache"
    geoip_city_path: str = "data/geoip/dbip-city-lite.mmdb"
    geoip_asn_path: str = "data/geoip/dbip-asn-lite.mmdb"
    dns_timeout_seconds: float = 3.0
    http_timeout_seconds: float = 4.0
    daily_external_request_limit: int = 500
    max_ip_lookups: int = 3
    max_domain_lookups: int = 4
    max_url_lookups: int = 5
    rdap_enabled: bool = True
    internetdb_enabled: bool = True
    tor_exit_list_enabled: bool = True

    scoring_enabled: bool = True
    scoring_version: str = "phase3-rules-v1"
    malicious_threshold: int = 70
    suspicious_threshold: int = 40
    family_min_points: int = 5
    auth_signal_max: int = 25
    domain_signal_max: int = 20
    ip_signal_max: int = 20
    content_signal_max: int = 20
    header_signal_max: int = 15

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="APP_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
