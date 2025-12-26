"""Core SSL/TLS scanning logic."""

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from .checks import (
    check_chain,
    check_ciphers,
    check_expiry,
    check_hostname,
    check_protocols,
)
from .config import Config, get_default_config
from .models import CheckResult, ScanResult, Severity
from .severity import calculate_overall_severity


def get_certificate(domain: str, port: int = 443, timeout: float = 10.0) -> x509.Certificate:
    """Fetch the X.509 certificate from a domain.
    
    Args:
        domain: Domain to connect to.
        port: Port number.
        timeout: Connection timeout in seconds.
        
    Returns:
        Parsed X.509 certificate.
        
    Raises:
        Various socket and SSL exceptions on failure.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We'll verify separately
    
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der is None:
                raise ssl.SSLError("No certificate received")
            return x509.load_der_x509_certificate(cert_der, default_backend())


def extract_cert_info(cert: x509.Certificate) -> tuple[str | None, str | None, datetime | None]:
    """Extract subject, issuer, and expiry from a certificate.
    
    Args:
        cert: X.509 certificate.
        
    Returns:
        Tuple of (subject, issuer, expiry_datetime).
    """
    # Extract subject (CN)
    subject = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        subject = cn_attrs[0].value
    
    # Extract issuer
    issuer = None
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if issuer_cn:
        issuer = issuer_cn[0].value
    else:
        # Try organization name as fallback
        issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if issuer_org:
            issuer = issuer_org[0].value
    
    # Get expiry
    expiry = cert.not_valid_after_utc
    
    return subject, issuer, expiry


def scan_domain(
    domain: str,
    port: int = 443,
    config: Config | None = None,
    timeout: float = 10.0,
) -> ScanResult:
    """Perform a complete SSL/TLS scan on a domain.
    
    Args:
        domain: Domain to scan.
        port: Port number (default 443).
        config: Configuration object. Uses defaults if None.
        timeout: Connection timeout in seconds.
        
    Returns:
        Complete scan result.
    """
    if config is None:
        config = get_default_config()
    
    severity_config = config.severity
    checks: list[CheckResult] = []
    
    # Clean domain (remove protocol if present)
    domain = domain.strip()
    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]
    # Remove trailing slash and path
    domain = domain.split("/")[0]
    # Remove port if specified in domain
    if ":" in domain:
        domain = domain.split(":")[0]
    
    try:
        # Get certificate
        cert = get_certificate(domain, port, timeout)
        subject, issuer, expiry = extract_cert_info(cert)
        
        # Run all checks
        checks.append(check_expiry(cert, severity_config))
        checks.append(check_chain(domain, port, severity_config, timeout))
        checks.append(check_protocols(domain, port, severity_config, timeout))
        checks.append(check_ciphers(domain, port, severity_config, timeout))
        checks.append(check_hostname(cert, domain, severity_config))
        
        # Calculate overall severity
        overall_severity = calculate_overall_severity(checks)
        
        return ScanResult(
            domain=domain,
            port=port,
            scanned_at=datetime.now(timezone.utc),
            overall_severity=overall_severity,
            checks=checks,
            cert_subject=subject,
            cert_issuer=issuer,
            cert_expiry=expiry,
        )
        
    except socket.timeout:
        return ScanResult(
            domain=domain,
            port=port,
            scanned_at=datetime.now(timezone.utc),
            overall_severity=Severity.CRITICAL,
            checks=[],
            error=f"Connection timed out after {timeout}s",
        )
        
    except socket.gaierror as e:
        return ScanResult(
            domain=domain,
            port=port,
            scanned_at=datetime.now(timezone.utc),
            overall_severity=Severity.CRITICAL,
            checks=[],
            error=f"DNS resolution failed: {e}",
        )
        
    except ConnectionRefusedError:
        return ScanResult(
            domain=domain,
            port=port,
            scanned_at=datetime.now(timezone.utc),
            overall_severity=Severity.CRITICAL,
            checks=[],
            error=f"Connection refused on port {port}",
        )
        
    except ssl.SSLError as e:
        return ScanResult(
            domain=domain,
            port=port,
            scanned_at=datetime.now(timezone.utc),
            overall_severity=Severity.CRITICAL,
            checks=[],
            error=f"SSL error: {e}",
        )
        
    except Exception as e:
        return ScanResult(
            domain=domain,
            port=port,
            scanned_at=datetime.now(timezone.utc),
            overall_severity=Severity.CRITICAL,
            checks=[],
            error=f"Scan failed: {e}",
        )


def scan_domains(
    domains: list[str],
    port: int = 443,
    config: Config | None = None,
    timeout: float = 10.0,
) -> list[ScanResult]:
    """Scan multiple domains.
    
    Args:
        domains: List of domains to scan.
        port: Port number.
        config: Configuration object.
        timeout: Connection timeout.
        
    Returns:
        List of scan results.
    """
    return [scan_domain(domain, port, config, timeout) for domain in domains]

