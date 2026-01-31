"""Configuration management for the malware analysis platform."""

import logging
from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

# Insecure default keys that should never be used in production
INSECURE_DEFAULT_KEYS = {"change-this-in-production", "changeme", "secret", "password", ""}


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Malware Analysis Platform"
    debug: bool = False
    api_key: str = "change-this-in-production"

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v):
        """Warn if using insecure default API key."""
        if v in INSECURE_DEFAULT_KEYS:
            logger.warning(
                "SECURITY WARNING: Using insecure default API key. "
                "Set the API_KEY environment variable to a secure value in production."
            )
        return v

    # Database
    database_url: str = "sqlite+aiosqlite:///./malware_analysis.db"

    # AWS S3
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    s3_bucket_name: str = "malware-analysis-artifacts"

    # Anthropic Claude API
    anthropic_api_key: Optional[str] = None
    claude_model: str = "claude-haiku-4-5-20241022"

    # VirusTotal
    virustotal_api_key: Optional[str] = None
    virustotal_rate_limit: int = 4  # requests per minute

    # Shodan
    shodan_api_key: Optional[str] = None

    # URLhaus
    urlhaus_api_url: str = "https://urlhaus-api.abuse.ch/v1"
    urlhaus_auth_key: Optional[str] = None

    # Google Safe Browsing
    google_safebrowsing_api_key: Optional[str] = None

    # IPQualityScore
    ipqualityscore_api_key: Optional[str] = None

    # CheckPhish
    checkphish_api_key: Optional[str] = None

    # n8n webhook configuration
    n8n_webhook_base_url: str = "http://localhost:5678/webhook"

    # File storage
    upload_dir: str = "./uploads"
    max_file_size: int = 50 * 1024 * 1024  # 50MB

    # Report settings
    report_retention_days: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
