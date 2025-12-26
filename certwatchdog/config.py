"""Configuration loader for CertWatchdog."""

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from .models import Severity


class SeverityThreshold(BaseModel):
    """Threshold configuration for a severity level."""
    cert_expiry_days: int | None = None
    protocols: list[str] = Field(default_factory=list)
    weak_ciphers: bool = False
    chain_invalid: bool = False
    hostname_mismatch: bool = False


class SeverityConfig(BaseModel):
    """Severity configuration."""
    critical: SeverityThreshold = Field(default_factory=SeverityThreshold)
    warning: SeverityThreshold = Field(default_factory=SeverityThreshold)
    info: SeverityThreshold = Field(default_factory=SeverityThreshold)


class WebhookConfig(BaseModel):
    """Webhook alerting configuration."""
    enabled: bool = False
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class EmailConfig(BaseModel):
    """Email alerting configuration (post-MVP)."""
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    to: list[str] = Field(default_factory=list)


class AlertingConfig(BaseModel):
    """Alerting configuration."""
    enabled: bool = False
    min_severity: str = "warning"
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)

    def should_alert(self, severity: Severity) -> bool:
        """Check if an alert should be sent for the given severity."""
        if not self.enabled:
            return False
        
        severity_order = {
            "ok": 0,
            "info": 1,
            "warning": 2,
            "critical": 3,
        }
        
        min_level = severity_order.get(self.min_severity, 2)
        actual_level = severity_order.get(severity.value, 0)
        
        return actual_level >= min_level


class Config(BaseModel):
    """Complete CertWatchdog configuration."""
    severity: SeverityConfig = Field(default_factory=SeverityConfig)
    domains: list[str] = Field(default_factory=list)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)


def substitute_env_vars(value: Any) -> Any:
    """Recursively substitute ${VAR} patterns with environment variables."""
    if isinstance(value, str):
        pattern = r'\$\{(\w+)\}'
        matches = re.findall(pattern, value)
        for match in matches:
            env_val = os.environ.get(match, "")
            value = value.replace(f"${{{match}}}", env_val)
        return value
    elif isinstance(value, dict):
        return {k: substitute_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [substitute_env_vars(item) for item in value]
    return value


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from a YAML file.
    
    Args:
        path: Path to configuration file. If None, returns default config.
        
    Returns:
        Loaded configuration object.
    """
    if path is None:
        return Config()
    
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    
    with open(path, "r") as f:
        raw_config = yaml.safe_load(f) or {}
    
    # Substitute environment variables
    raw_config = substitute_env_vars(raw_config)
    
    return Config.model_validate(raw_config)


def get_default_config() -> Config:
    """Get the default configuration."""
    return Config(
        severity=SeverityConfig(
            critical=SeverityThreshold(
                cert_expiry_days=7,
                protocols=["SSLv2", "SSLv3", "TLSv1.0"],
                weak_ciphers=True,
                chain_invalid=True,
                hostname_mismatch=True,
            ),
            warning=SeverityThreshold(
                cert_expiry_days=30,
                protocols=["TLSv1.1"],
            ),
            info=SeverityThreshold(
                cert_expiry_days=60,
            ),
        ),
    )


def generate_example_config() -> str:
    """Generate example configuration YAML content."""
    return """# CertWatchdog Configuration
# Customize severity thresholds and alerting settings

severity:
  critical:
    cert_expiry_days: 7
    protocols:
      - "SSLv2"
      - "SSLv3"
      - "TLSv1.0"
    weak_ciphers: true
    chain_invalid: true
    hostname_mismatch: true
  
  warning:
    cert_expiry_days: 30
    protocols:
      - "TLSv1.1"
  
  info:
    cert_expiry_days: 60

# Domains to monitor (for future watch mode)
domains:
  - example.com

# Alerting configuration
alerting:
  enabled: false
  min_severity: warning
  
  webhook:
    enabled: false
    url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    # headers:
    #   Authorization: "Bearer your-token"
"""

