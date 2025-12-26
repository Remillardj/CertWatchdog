"""Runtime settings management for CertWatchdog web UI."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

# Settings file location (in project directory)
SETTINGS_FILE = Path(__file__).parent.parent / "certwatchdog_settings.json"


class WebhookSettings(BaseModel):
    """Webhook configuration."""
    enabled: bool = False
    url: str = ""


class SeverityThresholds(BaseModel):
    """Expiry thresholds in days."""
    critical_days: int = Field(default=7, ge=1, le=365)
    warning_days: int = Field(default=30, ge=1, le=365)
    info_days: int = Field(default=60, ge=1, le=365)


class AlertSettings(BaseModel):
    """Alert configuration."""
    enabled: bool = False
    min_severity: str = "warning"  # critical, warning, info
    webhook: WebhookSettings = Field(default_factory=WebhookSettings)


class Settings(BaseModel):
    """Complete settings model."""
    severity: SeverityThresholds = Field(default_factory=SeverityThresholds)
    alerting: AlertSettings = Field(default_factory=AlertSettings)
    monitored_domains: list[str] = Field(default_factory=list)


# Global settings instance
_settings: Settings | None = None


def load_settings() -> Settings:
    """Load settings from file or return defaults."""
    global _settings
    
    if _settings is not None:
        return _settings
    
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
            _settings = Settings.model_validate(data)
            return _settings
        except Exception:
            pass
    
    _settings = Settings()
    return _settings


def save_settings(settings: Settings) -> bool:
    """Save settings to file."""
    global _settings
    
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings.model_dump(), f, indent=2)
        _settings = settings
        return True
    except Exception:
        return False


def get_settings() -> Settings:
    """Get current settings."""
    return load_settings()


def update_settings(data: dict[str, Any]) -> Settings:
    """Update settings with new values."""
    current = load_settings()
    updated_data = current.model_dump()
    
    # Deep merge the new data
    def deep_merge(base: dict, updates: dict) -> dict:
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                deep_merge(base[key], value)
            else:
                base[key] = value
        return base
    
    deep_merge(updated_data, data)
    new_settings = Settings.model_validate(updated_data)
    save_settings(new_settings)
    return new_settings


def settings_to_config(settings: Settings):
    """Convert web settings to scanner Config object."""
    from .config import (
        AlertingConfig,
        Config,
        SeverityConfig,
        SeverityThreshold,
        WebhookConfig,
    )
    
    return Config(
        severity=SeverityConfig(
            critical=SeverityThreshold(
                cert_expiry_days=settings.severity.critical_days,
                protocols=["SSLv2", "SSLv3", "TLSv1.0"],
                weak_ciphers=True,
                chain_invalid=True,
                hostname_mismatch=True,
            ),
            warning=SeverityThreshold(
                cert_expiry_days=settings.severity.warning_days,
                protocols=["TLSv1.1"],
            ),
            info=SeverityThreshold(
                cert_expiry_days=settings.severity.info_days,
            ),
        ),
        domains=settings.monitored_domains,
        alerting=AlertingConfig(
            enabled=settings.alerting.enabled,
            min_severity=settings.alerting.min_severity,
            webhook=WebhookConfig(
                enabled=settings.alerting.webhook.enabled,
                url=settings.alerting.webhook.url,
            ),
        ),
    )

