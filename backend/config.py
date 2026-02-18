"""Configuration management for RoboCop."""

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
    app_name: str = "RoboCop"
    debug: bool = False
    api_key: str = "change-this-in-production"

    # CORS configuration
    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v, info):
        """Validate API key security. Fails startup in production with insecure defaults."""
        if v in INSECURE_DEFAULT_KEYS:
            # In production (debug=False), refuse to start with insecure keys
            debug = info.data.get("debug", False)
            if not debug:
                raise ValueError(
                    "FATAL: Insecure default API key detected. "
                    "Set the API_KEY environment variable to a secure value (minimum 32 characters)."
                )
            logger.warning(
                "SECURITY WARNING: Using insecure default API key. "
                "Set the API_KEY environment variable to a secure value in production."
            )
        elif len(v) < 32:
            debug = info.data.get("debug", False)
            if not debug:
                raise ValueError(
                    f"FATAL: API key too short ({len(v)} chars). "
                    "Production API keys must be at least 32 characters."
                )
        return v

    # Database
    database_url: str = "sqlite+aiosqlite:///./malware_analysis.db"

    # AWS S3
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    s3_bucket_name: str = "robocop-artifacts"

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

    # GreyNoise
    greynoise_api_key: Optional[str] = None

    # AbuseIPDB
    abuseipdb_api_key: Optional[str] = None

    # urlscan.io
    urlscan_api_key: Optional[str] = None

    # AlienVault OTX
    alienvault_otx_api_key: Optional[str] = None

    # MalwareBazaar (abuse.ch)
    malwarebazaar_api_key: Optional[str] = None

    # n8n webhook configuration
    n8n_webhook_base_url: str = "http://localhost:5678/webhook"

    # File storage
    upload_dir: str = "./uploads"
    max_file_size: int = 50 * 1024 * 1024  # 50MB

    # NVD API (National Vulnerability Database)
    nvd_api_key: Optional[str] = None
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # MITRE ATT&CK
    mitre_attack_json_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    mitre_attack_cache_dir: str = "./data/mitre_cache"

    # Threat Intelligence Archive
    threat_intel_archive_dir: str = "./data/threat_archive"

    # Report settings
    report_retention_days: int = 30
    default_tlp_marking: str = "TLP:AMBER"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
