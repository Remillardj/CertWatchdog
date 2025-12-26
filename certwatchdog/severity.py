"""Severity engine for aggregating check results."""

from .models import CheckResult, Severity


def calculate_overall_severity(checks: list[CheckResult]) -> Severity:
    """Calculate the overall severity from a list of check results.
    
    The overall severity is the highest severity among all checks.
    
    Args:
        checks: List of check results.
        
    Returns:
        Highest severity level found.
    """
    if not checks:
        return Severity.OK
    
    # Find the highest severity
    overall = Severity.OK
    for check in checks:
        if check.severity > overall:
            overall = check.severity
    
    return overall


def get_severity_emoji(severity: Severity) -> str:
    """Get an emoji representation for a severity level.
    
    Args:
        severity: Severity level.
        
    Returns:
        Emoji string.
    """
    return {
        Severity.CRITICAL: "🔴",
        Severity.WARNING: "🟡",
        Severity.INFO: "🔵",
        Severity.OK: "🟢",
    }.get(severity, "⚪")


def get_severity_color(severity: Severity) -> str:
    """Get a Rich color name for a severity level.
    
    Args:
        severity: Severity level.
        
    Returns:
        Rich color name.
    """
    return {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
        Severity.OK: "green",
    }.get(severity, "white")


def get_check_icon(passed: bool) -> str:
    """Get an icon for check pass/fail status.
    
    Args:
        passed: Whether the check passed.
        
    Returns:
        Icon string.
    """
    return "✅" if passed else "❌"


def severity_to_css_class(severity: Severity) -> str:
    """Convert severity to a CSS class name for web UI.
    
    Args:
        severity: Severity level.
        
    Returns:
        CSS class name.
    """
    return {
        Severity.CRITICAL: "severity-critical",
        Severity.WARNING: "severity-warning",
        Severity.INFO: "severity-info",
        Severity.OK: "severity-ok",
    }.get(severity, "severity-unknown")

