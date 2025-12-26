"""Webhook alerting for Slack, Discord, and other services."""

import httpx

from ..config import AlertingConfig
from ..models import ScanResult


async def send_webhook_alert(
    result: ScanResult,
    config: AlertingConfig,
    timeout: float = 30.0,
) -> bool:
    """Send a webhook alert for a scan result.
    
    Args:
        result: Scan result to alert on.
        config: Alerting configuration.
        timeout: Request timeout in seconds.
        
    Returns:
        True if alert was sent successfully, False otherwise.
    """
    if not config.enabled or not config.webhook.enabled:
        return False
    
    if not config.should_alert(result.overall_severity):
        return False
    
    if not config.webhook.url:
        return False
    
    payload = result.to_alert_payload()
    
    # Format for Slack-compatible webhooks
    slack_payload = {
        "text": f"🔐 CertWatchdog Alert: {result.domain}",
        "attachments": [
            {
                "color": _severity_to_color(result.overall_severity.value),
                "title": f"{result.domain}:{result.port}",
                "fields": [
                    {
                        "title": "Severity",
                        "value": result.overall_severity.value.upper(),
                        "short": True,
                    },
                    {
                        "title": "Scanned At",
                        "value": result.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True,
                    },
                ],
                "text": _format_check_summary(result),
            }
        ],
        # Include raw payload for non-Slack webhooks
        "certwatchdog": payload,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.webhook.url,
                json=slack_payload,
                headers=config.webhook.headers,
                timeout=timeout,
            )
            response.raise_for_status()
            return True
            
    except httpx.HTTPError:
        return False
    except Exception:
        return False


def send_webhook_alert_sync(
    result: ScanResult,
    config: AlertingConfig,
    timeout: float = 30.0,
) -> bool:
    """Synchronous version of webhook alert.
    
    Args:
        result: Scan result to alert on.
        config: Alerting configuration.
        timeout: Request timeout in seconds.
        
    Returns:
        True if alert was sent successfully, False otherwise.
    """
    if not config.enabled or not config.webhook.enabled:
        return False
    
    if not config.should_alert(result.overall_severity):
        return False
    
    if not config.webhook.url:
        return False
    
    payload = result.to_alert_payload()
    
    slack_payload = {
        "text": f"🔐 CertWatchdog Alert: {result.domain}",
        "attachments": [
            {
                "color": _severity_to_color(result.overall_severity.value),
                "title": f"{result.domain}:{result.port}",
                "fields": [
                    {
                        "title": "Severity",
                        "value": result.overall_severity.value.upper(),
                        "short": True,
                    },
                    {
                        "title": "Scanned At",
                        "value": result.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True,
                    },
                ],
                "text": _format_check_summary(result),
            }
        ],
        "certwatchdog": payload,
    }
    
    try:
        with httpx.Client() as client:
            response = client.post(
                config.webhook.url,
                json=slack_payload,
                headers=config.webhook.headers,
                timeout=timeout,
            )
            response.raise_for_status()
            return True
            
    except httpx.HTTPError:
        return False
    except Exception:
        return False


def _severity_to_color(severity: str) -> str:
    """Convert severity to Slack attachment color."""
    return {
        "critical": "danger",
        "warning": "warning",
        "info": "#3498db",
        "ok": "good",
    }.get(severity, "#808080")


def _format_check_summary(result: ScanResult) -> str:
    """Format check results for Slack message."""
    if result.error:
        return f"❌ Error: {result.error}"
    
    lines = []
    for check in result.checks:
        icon = "✅" if check.passed else "❌"
        lines.append(f"{icon} {check.name}: {check.message}")
    
    return "\n".join(lines)

