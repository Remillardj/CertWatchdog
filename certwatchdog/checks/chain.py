"""Certificate chain validation check."""

import ssl
import socket
from typing import TYPE_CHECKING

import certifi

from ..models import CheckResult, Severity

if TYPE_CHECKING:
    from ..config import SeverityConfig


def check_chain(
    domain: str,
    port: int,
    severity_config: "SeverityConfig",
    timeout: float = 10.0,
) -> CheckResult:
    """Check certificate chain validity.
    
    Uses Python's ssl module with certifi's CA bundle to validate:
    - Certificate chain completeness
    - Root CA trust
    - Certificate expiration
    - Hostname verification
    
    Args:
        domain: Domain to check.
        port: Port number.
        severity_config: Severity configuration.
        timeout: Connection timeout in seconds.
        
    Returns:
        CheckResult with chain validation status.
    """
    try:
        # Create SSL context with certifi's CA bundle for reliable verification
        context = ssl.create_default_context(cafile=certifi.where())
        
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # If we get here, the chain validated successfully!
                # The context verifies the full chain against trusted CAs
                
                # Get certificate info for details
                cert_info = ssock.getpeercert()
                
                # Extract issuer info
                issuer = ""
                if cert_info and "issuer" in cert_info:
                    for rdn in cert_info["issuer"]:
                        for attr in rdn:
                            if attr[0] == "organizationName":
                                issuer = attr[1]
                                break
                            elif attr[0] == "commonName" and not issuer:
                                issuer = attr[1]
                
                return CheckResult(
                    name="Chain Validation",
                    passed=True,
                    severity=Severity.OK,
                    message=f"Chain verified ({issuer or 'trusted CA'})",
                    details={
                        "method": "certifi_trust_store",
                        "issuer": issuer,
                        "verified": True,
                    },
                )
                
    except ssl.SSLCertVerificationError as e:
        # Determine severity based on config
        severity = Severity.CRITICAL if severity_config.critical.chain_invalid else Severity.WARNING
        
        # Parse the error to provide useful information
        error_msg = str(e)
        if "self-signed" in error_msg.lower() or "self signed" in error_msg.lower():
            message = "Self-signed certificate detected"
        elif "expired" in error_msg.lower():
            message = "Certificate in chain has expired"
        elif "unable to get local issuer" in error_msg.lower():
            message = "Incomplete chain - missing intermediate certificate"
        elif "certificate has expired" in error_msg.lower():
            message = "Certificate has expired"
        elif "hostname" in error_msg.lower():
            message = "Hostname verification failed"
        else:
            # Truncate long error messages
            short_msg = error_msg[:100] + "..." if len(error_msg) > 100 else error_msg
            message = f"Chain validation failed: {short_msg}"
        
        return CheckResult(
            name="Chain Validation",
            passed=False,
            severity=severity,
            message=message,
            details={"error": error_msg},
        )
        
    except socket.timeout:
        return CheckResult(
            name="Chain Validation",
            passed=False,
            severity=Severity.CRITICAL,
            message="Connection timed out",
            details={"error": "timeout"},
        )
        
    except socket.gaierror as e:
        return CheckResult(
            name="Chain Validation",
            passed=False,
            severity=Severity.CRITICAL,
            message=f"DNS resolution failed: {e}",
            details={"error": str(e)},
        )
        
    except ConnectionRefusedError:
        return CheckResult(
            name="Chain Validation",
            passed=False,
            severity=Severity.CRITICAL,
            message="Connection refused",
            details={"error": "connection_refused"},
        )
        
    except Exception as e:
        # For any unexpected error, treat as validation failure
        severity = Severity.CRITICAL if severity_config.critical.chain_invalid else Severity.WARNING
        return CheckResult(
            name="Chain Validation",
            passed=False,
            severity=severity,
            message=f"Chain validation error: {type(e).__name__}",
            details={"error": str(e), "error_type": type(e).__name__},
        )
