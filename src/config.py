"""Centralized configuration loaded from environment variables."""

from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ASM_",
        extra="ignore",
    )

    # Redis
    redis_host: str = "192.168.1.21"
    redis_port: int = 6379
    redis_password: str | None = None
    redis_db: int = 0

    # ClickHouse
    ch_url: str = "http://192.168.1.21:8123/"
    ch_user: str = "default"
    ch_password: str | None = None
    ch_database: str = "asm_pipeline"

    # Producer identity
    producer_host: str = "laptop-001"

    # Stream tuning
    max_stream_len: int = 1_000_000
    batch_size: int = 5_000
    flush_interval: float = 5.0

    # Safety
    max_events_per_scan: int = 500_000

    # Scan behaviour
    scan_profile: Literal["stealth", "aggressive"] = "stealth"
    nuclei_input: Literal["services", "all-urls"] = "services"
    passive_analysis: bool = False

    # Logging
    log_level: str = "INFO"


settings = Settings()
