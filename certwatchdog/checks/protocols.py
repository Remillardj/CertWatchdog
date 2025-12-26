"""TLS protocol version check."""

import socket
import ssl
from typing import TYPE_CHECKING

from ..models import CheckResult, Severity

if TYPE_CHECKING:
    from ..config import SeverityConfig


# Protocol versions to test, mapped to their ssl module constants
PROTOCOL_TESTS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def test_protocol_support(
    domain: str,
    port: int,
    protocol_version: ssl.TLSVersion,
    timeout: float = 5.0,
) -> bool:
    """Test if a specific TLS protocol version is supported.
    
    Args:
        domain: Domain to test.
        port: Port number.
        protocol_version: TLS version to test.
        timeout: Connection timeout.
        
    Returns:
        True if protocol is supported, False otherwise.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = protocol_version
        context.maximum_version = protocol_version
        
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Connection succeeded with this protocol
                return True
                
    except (ssl.SSLError, socket.error, OSError):
        return False


def check_protocols(
    domain: str,
    port: int,
    severity_config: "SeverityConfig",
    timeout: float = 5.0,
) -> CheckResult:
    """Check for deprecated TLS/SSL protocol support.
    
    Args:
        domain: Domain to check.
        port: Port number.
        severity_config: Severity configuration.
        timeout: Connection timeout per protocol test.
        
    Returns:
        CheckResult with protocol support status.
    """
    supported_protocols = []
    deprecated_protocols = []
    
    # Test each protocol version
    for proto_name, proto_version in PROTOCOL_TESTS.items():
        if test_protocol_support(domain, port, proto_version, timeout):
            supported_protocols.append(proto_name)
    
    # Check for deprecated protocols
    critical_protocols = severity_config.critical.protocols
    warning_protocols = severity_config.warning.protocols
    
    severity = Severity.OK
    passed = True
    
    for proto in supported_protocols:
        if proto in critical_protocols:
            deprecated_protocols.append(proto)
            severity = Severity.CRITICAL
            passed = False
        elif proto in warning_protocols:
            deprecated_protocols.append(proto)
            if severity < Severity.WARNING:
                severity = Severity.WARNING
            passed = False
    
    # Generate message
    if not supported_protocols:
        return CheckResult(
            name="Protocol Support",
            passed=False,
            severity=Severity.CRITICAL,
            message="No TLS protocols supported (connection failed)",
            details={
                "supported": [],
                "deprecated": [],
            },
        )
    
    if deprecated_protocols:
        message = f"Deprecated protocols enabled: {', '.join(deprecated_protocols)}"
    elif "TLSv1.3" in supported_protocols:
        message = "Only modern protocols (TLS 1.2+) enabled"
    else:
        message = f"Supported: {', '.join(supported_protocols)}"
    
    return CheckResult(
        name="Protocol Support",
        passed=passed,
        severity=severity,
        message=message,
        details={
            "supported": supported_protocols,
            "deprecated": deprecated_protocols,
        },
    )

