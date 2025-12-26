"""Pydantic models for CertWatchdog scan results."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for check results."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"

    def __lt__(self, other: "Severity") -> bool:
        """Compare severity levels (CRITICAL > WARNING > INFO > OK)."""
        order = {
            Severity.OK: 0,
            Severity.INFO: 1,
            Severity.WARNING: 2,
            Severity.CRITICAL: 3,
        }
        return order[self] < order[other]

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other


class CheckResult(BaseModel):
    """Result of a single security check."""
    name: str = Field(description="Name of the check performed")
    passed: bool = Field(description="Whether the check passed")
    severity: Severity = Field(description="Severity level of the result")
    message: str = Field(description="Human-readable result message")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")


class ScanResult(BaseModel):
    """Complete scan result for a domain."""
    domain: str = Field(description="Scanned domain")
    port: int = Field(description="Port used for scan")
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    overall_severity: Severity = Field(description="Highest severity across all checks")
    checks: list[CheckResult] = Field(default_factory=list)
    cert_subject: str | None = Field(default=None, description="Certificate subject (CN)")
    cert_issuer: str | None = Field(default=None, description="Certificate issuer")
    cert_expiry: datetime | None = Field(default=None, description="Certificate expiration date")
    error: str | None = Field(default=None, description="Error message if scan failed")

    @property
    def is_error(self) -> bool:
        """Check if the scan resulted in an error."""
        return self.error is not None

    def to_alert_payload(self) -> dict[str, Any]:
        """Convert scan result to webhook alert payload."""
        return {
            "tool": "certwatchdog",
            "domain": self.domain,
            "port": self.port,
            "severity": self.overall_severity.value,
            "message": self._get_summary_message(),
            "checks": [check.model_dump() for check in self.checks],
            "scanned_at": self.scanned_at.isoformat() + "Z",
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_expiry": self.cert_expiry.isoformat() if self.cert_expiry else None,
        }

    def _get_summary_message(self) -> str:
        """Generate a summary message for alerts."""
        if self.error:
            return f"Scan failed: {self.error}"
        
        failed_checks = [c for c in self.checks if not c.passed]
        if not failed_checks:
            return "All checks passed"
        
        critical = [c for c in failed_checks if c.severity == Severity.CRITICAL]
        warnings = [c for c in failed_checks if c.severity == Severity.WARNING]
        
        parts = []
        if critical:
            parts.append(f"{len(critical)} critical issue(s)")
        if warnings:
            parts.append(f"{len(warnings)} warning(s)")
        
        return ", ".join(parts) if parts else "Issues detected"

