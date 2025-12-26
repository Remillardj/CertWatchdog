"""FastAPI web server for CertWatchdog."""

import os
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .alerting.webhook import send_webhook_alert_sync
from .config import get_default_config, load_config
from .models import Severity
from .scanner import scan_domain
from .settings import (
    Settings,
    get_settings,
    save_settings,
    settings_to_config,
    update_settings,
)
from .severity import get_check_icon, get_severity_emoji

# Determine paths
BASE_DIR = Path(__file__).parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Create FastAPI app
app = FastAPI(
    title="CertWatchdog",
    description="SSL/TLS Health Checker",
    version="0.1.0",
)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Setup templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Add custom template filters
templates.env.filters["severity_emoji"] = get_severity_emoji
templates.env.filters["check_icon"] = get_check_icon


def get_config():
    """Get configuration from settings or environment."""
    # First check for settings file
    settings = get_settings()
    if settings:
        return settings_to_config(settings)
    
    # Fall back to env-specified config file
    config_path = os.environ.get("CERTWATCHDOG_CONFIG")
    if config_path:
        try:
            return load_config(config_path)
        except Exception:
            pass
    return get_default_config()


def severity_to_tailwind_class(severity: Severity) -> str:
    """Convert severity to Tailwind CSS classes."""
    return {
        Severity.CRITICAL: "bg-red-500/20 border-red-500 text-red-300",
        Severity.WARNING: "bg-amber-500/20 border-amber-500 text-amber-300",
        Severity.INFO: "bg-blue-500/20 border-blue-500 text-blue-300",
        Severity.OK: "bg-emerald-500/20 border-emerald-500 text-emerald-300",
    }.get(severity, "bg-gray-500/20 border-gray-500 text-gray-300")


def severity_to_badge_class(severity: Severity) -> str:
    """Convert severity to Tailwind badge classes."""
    return {
        Severity.CRITICAL: "bg-red-500 text-white",
        Severity.WARNING: "bg-amber-500 text-black",
        Severity.INFO: "bg-blue-500 text-white",
        Severity.OK: "bg-emerald-500 text-white",
    }.get(severity, "bg-gray-500 text-white")


# Add to template context
templates.env.globals["severity_to_tailwind_class"] = severity_to_tailwind_class
templates.env.globals["severity_to_badge_class"] = severity_to_badge_class


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the main dashboard page."""
    settings = get_settings()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "settings": settings},
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    domain: str = Form(...),
    port: int = Form(443),
    send_alert: bool = Form(False),
):
    """Perform a scan and return results as HTML partial."""
    config = get_config()
    settings = get_settings()
    
    # Clean and validate domain
    domain = domain.strip()
    if not domain:
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "error": "Please enter a domain name",
                "result": None,
                "alert_sent": False,
            },
        )
    
    # Perform scan
    result = scan_domain(domain, port, config)
    
    # Send alert if enabled and severity warrants it
    alert_sent = False
    if send_alert and settings.alerting.enabled and settings.alerting.webhook.enabled:
        if config.alerting.should_alert(result.overall_severity):
            alert_sent = send_webhook_alert_sync(result, config.alerting)
    
    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "result": result,
            "error": None,
            "alert_sent": alert_sent,
        },
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Render the settings page."""
    settings = get_settings()
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "settings": settings},
    )


@app.post("/settings/save", response_class=HTMLResponse)
async def save_settings_route(
    request: Request,
    critical_days: int = Form(7),
    warning_days: int = Form(30),
    info_days: int = Form(60),
    alerting_enabled: bool = Form(False),
    min_severity: str = Form("warning"),
    webhook_enabled: bool = Form(False),
    webhook_url: str = Form(""),
    monitored_domains: str = Form(""),
):
    """Save settings from the form."""
    # Parse monitored domains (one per line)
    domains = [d.strip() for d in monitored_domains.split("\n") if d.strip()]
    
    # Update settings
    new_settings = Settings(
        severity={
            "critical_days": critical_days,
            "warning_days": warning_days,
            "info_days": info_days,
        },
        alerting={
            "enabled": alerting_enabled,
            "min_severity": min_severity,
            "webhook": {
                "enabled": webhook_enabled,
                "url": webhook_url,
            },
        },
        monitored_domains=domains,
    )
    
    success = save_settings(new_settings)
    
    return templates.TemplateResponse(
        "settings_saved.html",
        {"request": request, "success": success, "settings": new_settings},
    )


@app.post("/settings/test-webhook", response_class=HTMLResponse)
async def test_webhook(request: Request, webhook_url: str = Form(...)):
    """Test the webhook configuration."""
    if not webhook_url:
        return templates.TemplateResponse(
            "webhook_test_result.html",
            {"request": request, "success": False, "message": "No webhook URL provided"},
        )
    
    # Send a test payload
    test_payload = {
        "text": "🔐 CertWatchdog Test Alert",
        "attachments": [
            {
                "color": "good",
                "title": "Webhook Test",
                "text": "✅ Your webhook is configured correctly!",
                "fields": [
                    {"title": "Status", "value": "Test Successful", "short": True},
                ],
            }
        ],
    }
    
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(webhook_url, json=test_payload)
            response.raise_for_status()
            
        return templates.TemplateResponse(
            "webhook_test_result.html",
            {"request": request, "success": True, "message": "Webhook test successful!"},
        )
    except httpx.HTTPError as e:
        return templates.TemplateResponse(
            "webhook_test_result.html",
            {"request": request, "success": False, "message": f"HTTP error: {e}"},
        )
    except Exception as e:
        return templates.TemplateResponse(
            "webhook_test_result.html",
            {"request": request, "success": False, "message": f"Error: {e}"},
        )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/scan/{domain}")
async def api_scan(domain: str, port: int = 443):
    """API endpoint for programmatic scanning."""
    config = get_config()
    result = scan_domain(domain, port, config)
    return result.model_dump()


@app.get("/api/settings")
async def api_settings():
    """API endpoint to get current settings."""
    return get_settings().model_dump()
