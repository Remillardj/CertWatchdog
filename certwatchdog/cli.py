"""Typer CLI for CertWatchdog."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .alerting.webhook import send_webhook_alert_sync
from .config import generate_example_config, load_config
from .models import ScanResult, Severity
from .scanner import scan_domain, scan_domains
from .severity import get_check_icon, get_severity_color, get_severity_emoji

app = typer.Typer(
    name="certwatchdog",
    help="SSL/TLS Health Checker - Scan domains for certificate and TLS issues",
    add_completion=False,
)

config_app = typer.Typer(help="Configuration management commands")
app.add_typer(config_app, name="config")

console = Console()


def print_scan_result(result: ScanResult, json_output: bool = False) -> None:
    """Print a scan result to the console.
    
    Args:
        result: Scan result to display.
        json_output: If True, output as JSON.
    """
    if json_output:
        console.print_json(result.model_dump_json())
        return
    
    # Handle errors
    if result.is_error:
        console.print()
        console.print(Panel(
            f"[red bold]Error:[/red bold] {result.error}",
            title=f"[red]{result.domain}:{result.port}[/red]",
            border_style="red",
        ))
        return
    
    # Create results table
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        expand=True,
    )
    table.add_column("Icon", width=3)
    table.add_column("Check", width=20)
    table.add_column("Message")
    
    for check in result.checks:
        icon = get_check_icon(check.passed)
        color = get_severity_color(check.severity)
        table.add_row(
            icon,
            check.name,
            f"[{color}]{check.message}[/{color}]",
        )
    
    # Create header with overall severity
    severity_emoji = get_severity_emoji(result.overall_severity)
    severity_color = get_severity_color(result.overall_severity)
    severity_text = result.overall_severity.value.upper()
    
    header = Text()
    header.append(f"{result.domain}\n", style="bold white")
    header.append(f"Overall: {severity_emoji} ", style="bold")
    header.append(severity_text, style=f"bold {severity_color}")
    
    # Create panel
    console.print()
    console.print(Panel(
        table,
        title=header,
        border_style=severity_color,
        padding=(1, 2),
    ))
    
    # Certificate details
    if result.cert_subject or result.cert_issuer or result.cert_expiry:
        console.print()
        if result.cert_subject:
            console.print(f"[dim]Certificate:[/dim] {result.cert_subject}")
        if result.cert_issuer:
            console.print(f"[dim]Issuer:[/dim] {result.cert_issuer}")
        if result.cert_expiry:
            console.print(f"[dim]Expires:[/dim] {result.cert_expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}")


@app.command("check")
def check_command(
    domain: Annotated[
        Optional[str],
        typer.Argument(help="Domain to check (e.g., example.com)"),
    ] = None,
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="File containing domains (one per line)"),
    ] = None,
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Port to connect to"),
    ] = 443,
    config_path: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output results as JSON"),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Connection timeout in seconds"),
    ] = 10.0,
    alert: Annotated[
        bool,
        typer.Option("--alert", "-a", help="Send alerts if configured"),
    ] = False,
) -> None:
    """Check SSL/TLS configuration for one or more domains."""
    # Validate arguments
    if domain is None and file is None:
        console.print("[red]Error:[/red] Please provide a domain or --file option")
        raise typer.Exit(1)
    
    # Load config
    config = None
    if config_path:
        try:
            config = load_config(config_path)
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Config file not found: {config_path}")
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to load config: {e}")
            raise typer.Exit(1)
    
    # Collect domains to scan
    domains_to_scan: list[str] = []
    
    if domain:
        domains_to_scan.append(domain)
    
    if file:
        if not file.exists():
            console.print(f"[red]Error:[/red] File not found: {file}")
            raise typer.Exit(1)
        
        with open(file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains_to_scan.append(line)
    
    if not domains_to_scan:
        console.print("[red]Error:[/red] No domains to scan")
        raise typer.Exit(1)
    
    # Scan domains
    has_critical = False
    has_warning = False
    
    for domain_to_scan in domains_to_scan:
        if not json_output:
            console.print(f"\n[dim]🔍 Scanning {domain_to_scan}:{port}...[/dim]")
        
        result = scan_domain(domain_to_scan, port, config, timeout)
        print_scan_result(result, json_output)
        
        # Track overall status
        if result.overall_severity == Severity.CRITICAL:
            has_critical = True
        elif result.overall_severity == Severity.WARNING:
            has_warning = True
        
        # Send alerts if configured
        if alert and config and config.alerting.enabled:
            if config.alerting.should_alert(result.overall_severity):
                sent = send_webhook_alert_sync(result, config.alerting)
                if sent and not json_output:
                    console.print("[dim]📤 Alert sent[/dim]")
    
    # Exit with appropriate code
    if has_critical:
        raise typer.Exit(2)
    elif has_warning:
        raise typer.Exit(1)


@app.command("serve")
def serve_command(
    host: Annotated[
        str,
        typer.Option("--host", "-h", help="Host to bind to"),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Port to listen on"),
    ] = 8000,
    config_path: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
    reload: Annotated[
        bool,
        typer.Option("--reload", "-r", help="Enable auto-reload for development"),
    ] = False,
) -> None:
    """Start the web UI server."""
    import uvicorn
    
    console.print(f"\n[bold green]🚀 Starting CertWatchdog Web UI[/bold green]")
    console.print(f"[dim]→ http://{host}:{port}[/dim]\n")
    
    # Set config path in environment for the server to pick up
    import os
    if config_path:
        os.environ["CERTWATCHDOG_CONFIG"] = str(config_path)
    
    uvicorn.run(
        "certwatchdog.server:app",
        host=host,
        port=port,
        reload=reload,
    )


@config_app.command("init")
def config_init_command(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output file path"),
    ] = Path("config.yaml"),
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing file"),
    ] = False,
) -> None:
    """Generate an example configuration file."""
    if output.exists() and not force:
        console.print(f"[red]Error:[/red] File already exists: {output}")
        console.print("[dim]Use --force to overwrite[/dim]")
        raise typer.Exit(1)
    
    content = generate_example_config()
    with open(output, "w") as f:
        f.write(content)
    
    console.print(f"[green]✓[/green] Created configuration file: {output}")


@config_app.command("validate")
def config_validate_command(
    config_file: Annotated[
        Path,
        typer.Argument(help="Configuration file to validate"),
    ],
) -> None:
    """Validate a configuration file."""
    if not config_file.exists():
        console.print(f"[red]Error:[/red] File not found: {config_file}")
        raise typer.Exit(1)
    
    try:
        config = load_config(config_file)
        console.print(f"[green]✓[/green] Configuration is valid")
        
        # Show summary
        console.print()
        console.print("[bold]Severity Thresholds:[/bold]")
        console.print(f"  Critical expiry: {config.severity.critical.cert_expiry_days} days")
        console.print(f"  Warning expiry: {config.severity.warning.cert_expiry_days} days")
        console.print(f"  Info expiry: {config.severity.info.cert_expiry_days} days")
        
        if config.domains:
            console.print()
            console.print(f"[bold]Monitored Domains:[/bold] {len(config.domains)}")
            for domain in config.domains[:5]:
                console.print(f"  • {domain}")
            if len(config.domains) > 5:
                console.print(f"  [dim]... and {len(config.domains) - 5} more[/dim]")
        
        if config.alerting.enabled:
            console.print()
            console.print("[bold]Alerting:[/bold] Enabled")
            console.print(f"  Min severity: {config.alerting.min_severity}")
            if config.alerting.webhook.enabled:
                console.print(f"  Webhook: Configured")
                
    except Exception as e:
        console.print(f"[red]Error:[/red] Invalid configuration: {e}")
        raise typer.Exit(1)


@app.command("version")
def version_command() -> None:
    """Show version information."""
    console.print(f"[bold]CertWatchdog[/bold] v{__version__}")


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()

