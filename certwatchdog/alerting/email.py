"""Email alerting (post-MVP placeholder)."""

from ..config import AlertingConfig
from ..models import ScanResult


def send_email_alert(
    result: ScanResult,
    config: AlertingConfig,
) -> bool:
    """Send an email alert for a scan result.
    
    Note: This is a post-MVP feature placeholder.
    
    Args:
        result: Scan result to alert on.
        config: Alerting configuration.
        
    Returns:
        True if alert was sent successfully, False otherwise.
    """
    # Post-MVP: Implement SMTP email sending
    # Will use smtplib with config.email settings
    return False

