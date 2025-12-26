"""Cipher strength check."""

import re
import socket
import ssl
from typing import TYPE_CHECKING

from ..models import CheckResult, Severity

if TYPE_CHECKING:
    from ..config import SeverityConfig


# Patterns for weak ciphers
WEAK_CIPHER_PATTERNS = [
    r"NULL",           # No encryption
    r"EXPORT",         # Export-grade (weak) ciphers
    r"DES(?!-)",       # Single DES (not 3DES)
    r"RC4",            # RC4 stream cipher
    r"RC2",            # RC2 cipher
    r"MD5",            # MD5 for MAC
    r"ANON",           # Anonymous (no authentication)
    r"ADH",            # Anonymous Diffie-Hellman
    r"AECDH",          # Anonymous ECDH
    r"^EXP-",          # Export ciphers
    r"DES-CBC-SHA$",   # Weak DES
    r"DES-CBC3-SHA$",  # 3DES (deprecated)
]

# Compile patterns for efficiency
WEAK_PATTERNS_COMPILED = [re.compile(p, re.IGNORECASE) for p in WEAK_CIPHER_PATTERNS]


def is_weak_cipher(cipher_name: str) -> bool:
    """Check if a cipher is considered weak.
    
    Args:
        cipher_name: Name of the cipher suite.
        
    Returns:
        True if the cipher is weak, False otherwise.
    """
    for pattern in WEAK_PATTERNS_COMPILED:
        if pattern.search(cipher_name):
            return True
    return False


def check_ciphers(
    domain: str,
    port: int,
    severity_config: "SeverityConfig",
    timeout: float = 10.0,
) -> CheckResult:
    """Check for weak cipher suite support.
    
    Args:
        domain: Domain to check.
        port: Port number.
        severity_config: Severity configuration.
        timeout: Connection timeout.
        
    Returns:
        CheckResult with cipher strength status.
    """
    try:
        # Create context that accepts all ciphers (for testing purposes)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Get the default ciphers and what's actually negotiated
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the negotiated cipher
                negotiated_cipher = ssock.cipher()
                
                if negotiated_cipher is None:
                    return CheckResult(
                        name="Cipher Strength",
                        passed=False,
                        severity=Severity.CRITICAL,
                        message="No cipher negotiated",
                        details={"error": "cipher_negotiation_failed"},
                    )
                
                cipher_name = negotiated_cipher[0]
                protocol_version = negotiated_cipher[1]
                key_bits = negotiated_cipher[2]
                
                # Check if the negotiated cipher is weak
                weak_ciphers = []
                if is_weak_cipher(cipher_name):
                    weak_ciphers.append(cipher_name)
                
                # Also check key strength
                if key_bits and key_bits < 128:
                    weak_ciphers.append(f"{cipher_name} ({key_bits}-bit key)")
                
                if weak_ciphers:
                    severity = Severity.CRITICAL if severity_config.critical.weak_ciphers else Severity.WARNING
                    return CheckResult(
                        name="Cipher Strength",
                        passed=False,
                        severity=severity,
                        message=f"Weak cipher in use: {weak_ciphers[0]}",
                        details={
                            "negotiated_cipher": cipher_name,
                            "protocol": protocol_version,
                            "key_bits": key_bits,
                            "weak_ciphers": weak_ciphers,
                        },
                    )
                
                return CheckResult(
                    name="Cipher Strength",
                    passed=True,
                    severity=Severity.OK,
                    message=f"Strong cipher: {cipher_name}",
                    details={
                        "negotiated_cipher": cipher_name,
                        "protocol": protocol_version,
                        "key_bits": key_bits,
                    },
                )
                
    except socket.timeout:
        return CheckResult(
            name="Cipher Strength",
            passed=False,
            severity=Severity.CRITICAL,
            message="Connection timed out",
            details={"error": "timeout"},
        )
        
    except socket.gaierror as e:
        return CheckResult(
            name="Cipher Strength",
            passed=False,
            severity=Severity.CRITICAL,
            message=f"DNS resolution failed: {e}",
            details={"error": str(e)},
        )
        
    except Exception as e:
        return CheckResult(
            name="Cipher Strength",
            passed=False,
            severity=Severity.CRITICAL,
            message=f"Cipher check failed: {e}",
            details={"error": str(e)},
        )

