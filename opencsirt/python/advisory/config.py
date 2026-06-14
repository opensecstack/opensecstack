"""Runtime configuration loaded from OPENCSIRT_PY_* environment variables.

Mirrors the 12-factor pattern used by the Go control plane in
opencsirt/cmd/. The Settings object is constructed once at startup and
injected into the FastAPI app state — handlers reach it via the
get_settings() dependency.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide configuration."""

    model_config = SettingsConfigDict(
        env_prefix="OPENCSIRT_PY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # HTTP server
    port: int = 8089
    host: str = "0.0.0.0"
    log_level: str = "INFO"

    # Auth — shared HS256 secret with the Go core. Empty disables the
    # middleware (dev only); fail-closed otherwise.
    jwt_secret: str = ""
    jwt_issuer: str = "opencsirt"
    dev_mode: bool = False

    # Enricher API keys. Each enricher self-disables when its key is
    # empty so a partial deployment still serves /enrich/iocs.
    vt_api_key: str = ""
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""

    # Optional Redis cache for enrichment results. Empty → in-memory
    # fallback (process-local LRU).
    redis_url: str = ""
    enrich_cache_ttl_seconds: int = 3600

    # CSAF publisher metadata.
    publisher_name: str = "OpenCSIRT"
    publisher_namespace: str = "https://opencsirt.example.org"
    publisher_category: str = "coordinator"
    publisher_contact: str = "csirt@opencsirt.example.org"

    # YARA rule directory. Resolved relative to the package by default.
    yara_rules_dir: str = ""

    # HTTP client timeouts.
    enricher_timeout_seconds: float = 8.0

    # Default TLP marking for generated advisories.
    default_tlp: str = "AMBER"

    rate_limit_per_minute: int = Field(default=60, ge=1)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide Settings instance."""
    return Settings()


def reset_settings_cache() -> None:
    """Drop the lru_cache — used by tests that mutate env vars."""
    get_settings.cache_clear()
