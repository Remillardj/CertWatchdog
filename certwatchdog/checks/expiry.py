"""Certificate expiration check."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cryptography import x509

from ..models import CheckResult, Severity

if TYPE_CHECKING:
    from ..config import SeverityConfig


def check_expiry(
    cert: x509.Certificate,
    severity_config: "SeverityConfig",
) -> CheckResult:
    """Check certificate expiration date.
    
    Args:
        cert: The X.509 certificate to check.
        severity_config: Severity configuration for thresholds.
        
    Returns:
        CheckResult with expiry status.
    """
    now = datetime.now(timezone.utc)
    expiry = cert.not_valid_after_utc
    days_until_expiry = (expiry - now).days
    
    # Determine severity based on days until expiry
    severity = Severity.OK
    passed = True
    
    # Check thresholds from most severe to least
    if severity_config.critical.cert_expiry_days is not None:
        if days_until_expiry <= severity_config.critical.cert_expiry_days:
            severity = Severity.CRITICAL
            passed = False
    
    if severity == Severity.OK and severity_config.warning.cert_expiry_days is not None:
        if days_until_expiry <= severity_config.warning.cert_expiry_days:
            severity = Severity.WARNING
            passed = False
    
    if severity == Severity.OK and severity_config.info.cert_expiry_days is not None:
        if days_until_expiry <= severity_config.info.cert_expiry_days:
            severity = Severity.INFO
            # Info is just informational, still counts as passed
            passed = True
    
    # Handle already expired certificates
    if days_until_expiry < 0:
        severity = Severity.CRITICAL
        passed = False
        message = f"Certificate EXPIRED {abs(days_until_expiry)} days ago"
    elif days_until_expiry == 0:
        severity = Severity.CRITICAL
        passed = False
        message = "Certificate expires TODAY"
    else:
        message = f"Expires in {days_until_expiry} days"
    
    return CheckResult(
        name="Certificate Expiry",
        passed=passed,
        severity=severity,
        message=message,
        details={
            "expiry_date": expiry.isoformat(),
            "days_until_expiry": days_until_expiry,
        },
    )

