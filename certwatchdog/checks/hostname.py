"""Hostname verification check."""

import fnmatch
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import CheckResult, Severity

if TYPE_CHECKING:
    from ..config import SeverityConfig


def get_certificate_names(cert: x509.Certificate) -> tuple[str | None, list[str]]:
    """Extract Common Name and Subject Alternative Names from certificate.
    
    Args:
        cert: X.509 certificate to parse.
        
    Returns:
        Tuple of (common_name, list_of_sans).
    """
    # Get Common Name
    cn = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        cn = cn_attrs[0].value
    
    # Get Subject Alternative Names
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    
    return cn, sans


def matches_hostname(cert_name: str, hostname: str) -> bool:
    """Check if a certificate name matches the hostname.
    
    Handles wildcard certificates (e.g., *.example.com).
    
    Args:
        cert_name: Name from certificate (CN or SAN).
        hostname: Hostname to match against.
        
    Returns:
        True if the names match.
    """
    cert_name = cert_name.lower()
    hostname = hostname.lower()
    
    # Exact match
    if cert_name == hostname:
        return True
    
    # Wildcard match
    if cert_name.startswith("*."):
        # *.example.com should match foo.example.com but not foo.bar.example.com
        wildcard_domain = cert_name[2:]  # Remove "*."
        
        # Check if hostname ends with the wildcard domain
        if hostname.endswith("." + wildcard_domain) or hostname == wildcard_domain:
            # Ensure there's only one level before the wildcard domain
            prefix = hostname[: -(len(wildcard_domain) + 1)] if hostname != wildcard_domain else ""
            if "." not in prefix:
                return True
    
    # Use fnmatch for more complex patterns (though rare in certs)
    if fnmatch.fnmatch(hostname, cert_name):
        return True
    
    return False


def check_hostname(
    cert: x509.Certificate,
    domain: str,
    severity_config: "SeverityConfig",
) -> CheckResult:
    """Check if the certificate matches the target hostname.
    
    Args:
        cert: X.509 certificate to check.
        domain: Domain name to verify.
        severity_config: Severity configuration.
        
    Returns:
        CheckResult with hostname match status.
    """
    cn, sans = get_certificate_names(cert)
    
    # Collect all names to check
    all_names = sans.copy()
    if cn and cn not in all_names:
        all_names.append(cn)
    
    if not all_names:
        severity = Severity.CRITICAL if severity_config.critical.hostname_mismatch else Severity.WARNING
        return CheckResult(
            name="Hostname Match",
            passed=False,
            severity=severity,
            message="No names found in certificate",
            details={
                "common_name": cn,
                "sans": sans,
                "checked_domain": domain,
            },
        )
    
    # Check if domain matches any name
    for name in all_names:
        if matches_hostname(name, domain):
            return CheckResult(
                name="Hostname Match",
                passed=True,
                severity=Severity.OK,
                message="Certificate matches domain",
                details={
                    "matched_name": name,
                    "common_name": cn,
                    "sans": sans,
                    "checked_domain": domain,
                },
            )
    
    # No match found
    severity = Severity.CRITICAL if severity_config.critical.hostname_mismatch else Severity.WARNING
    
    return CheckResult(
        name="Hostname Match",
        passed=False,
        severity=severity,
        message=f"Certificate does not match '{domain}'",
        details={
            "common_name": cn,
            "sans": sans,
            "checked_domain": domain,
            "available_names": all_names,
        },
    )

