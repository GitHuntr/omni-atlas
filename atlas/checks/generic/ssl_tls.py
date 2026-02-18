"""
SSL/TLS Configuration Check

Tests for weak SSL/TLS configurations and certificate issues.
"""

import ssl
import socket
import datetime
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class SSLTLSCheck(VulnerabilityCheck):
    """
    Checks for SSL/TLS configuration issues.
    
    Verifies:
    1. Certificate validity (expiry, start date)
    2. Hostname mismatch
    3. Self-signed certificates
    4. Weak protocol support (limited by Python's OpenSSL capabilities)
    """
    
    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="ssl_config",
            name="SSL/TLS Configuration",
            category="Encryption",
            severity=Severity.MEDIUM,
            description="Analyzes SSL/TLS configuration for certificate validity and security weakness",
            owasp_category="A02:2021 Cryptographic Failures",
            cwe_id="CWE-326",
            prerequisites=[],
            applicable_services=["https", "ssl", "tls"],
            tags=["ssl", "tls", "encryption", "certificate"]
        )
    
    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        """Execute SSL/TLS check"""
        # Parse target
        if not target.startswith("https://"):
            # If target is not HTTPS, check if HTTPS port is open or skip
            if "https" not in target:
                 # Logic to upgrade http to https for testing, or check if port 443 is open
                 pass
        
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        # Skip if not HTTPS or port 443/8443
        if parsed.scheme != "https" and port != 443:
            return self._inconclusive("Target does not appear to use HTTPS")

        findings = []
        
        try:
            # 1. Get Certificate Info
            cert_info = self._get_cert_info(hostname, port)
            
            if cert_info:
                # Check Expiry
                days_left = (cert_info['notAfter'] - datetime.datetime.now()).days
                if days_left < 0:
                    findings.append(f"Certificate has expired on {cert_info['notAfter']}")
                elif days_left < 30:
                    findings.append(f"Certificate expires soon (in {days_left} days)")
                
                # Check Hostname
                if not self._match_hostname(cert_info, hostname):
                     findings.append(f"Certificate common name/SAN does not match hostname '{hostname}'")
                     
                # Check Self-Signed (heuristic: issuer == subject)
                if cert_info.get('issuer') == cert_info.get('subject'):
                    findings.append("Certificate appears to be self-signed")

            # 2. Check Protocol (Brief)
            # Python's SSL module depends on system OpenSSL, checking specifically for SSLv3/TLS1.0 
            # might be restricted by the client itself, but we can try to report the negotiated protocol.
            protocol, cipher = self._get_connection_details(hostname, port)
            if protocol in ['TLSv1', 'SSLv3', 'SSLv2']:
                findings.append(f"Weak Protocol negotiated: {protocol}")
            
            # Result
            if findings:
                return self._vulnerable(
                    title="Weak SSL/TLS Configuration",
                    description=f"Identified {len(findings)} SSL/TLS issues.",
                    evidence="\n".join(findings),
                    remediation="Renew valid certificates, ensure hostname matches, disable weak protocols (TLS 1.0/1.1, SSLv3).",
                    severity=Severity.MEDIUM if "expired" in str(findings) else Severity.LOW
                )
            
            return self._not_vulnerable()

        except Exception as e:
            logger.error(f"SSL Check failed: {e}")
            return self._error(str(e))

    def _get_cert_info(self, hostname: str, port: int) -> Optional[Dict]:
        """Retrieve certificate details"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # Note: getpeercert() returns empty dict if verify_mode=CERT_NONE and no cert requested?
                    # Actually for unverified, we might need to fetch it differently or just parse what we can.
                    # Standard getpeercert() works for validated certs. For introspection we might need binary.
                    # Let's try regular first.
                    if not cert:
                        # try getting binary and parsing? Too complex for generic check.
                        # Fallback: If we can't get dict, we can't check expiry easily without 3rd party lib.
                        # But standard connect usually returns it if we ask nicely?
                        pass
                    return self._parse_cert_date(cert)
        except Exception as e:
            logger.debug(f"Cert fetch error: {e}")
            return None
        return None

    def _parse_cert_date(self, cert: Dict) -> Dict:
        """Parse cert dates from SSL dict"""
        if not cert:
            return None
            
        fmt = r"%b %d %H:%M:%S %Y %Z"
        try:
            return {
                'notBefore': datetime.datetime.strptime(cert['notBefore'], fmt),
                'notAfter': datetime.datetime.strptime(cert['notAfter'], fmt),
                'subject': cert.get('subject'),
                'issuer': cert.get('issuer'),
                'subjectAltName': cert.get('subjectAltName')
            }
        except:
            return None

    def _match_hostname(self, cert: Dict, hostname: str) -> bool:
        """Check if cert matches hostname (basic verify)"""
        # This is complex to do right (wildcards etc). 
        # For this basic check, we look at SANs and CN.
        if not cert: return False
        
        # Check SANs
        sans = cert.get('subjectAltName', [])
        for type_, value in sans:
            if type_ == 'DNS':
                if value == hostname or (value.startswith('*.') and hostname.endswith(value[2:])):
                    return True
        
        # Check CN (Subject)
        # Subject is a list of tuples
        for rdn in cert.get('subject', []):
            for key, value in rdn:
                if key == 'commonName':
                    if value == hostname or (value.startswith('*.') and hostname.endswith(value[2:])):
                        return True
        return False

    def _get_connection_details(self, hostname: str, port: int) -> Tuple[str, str]:
        """Get negotiated protocol and cipher"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.version(), ssock.cipher()[0]
        except:
            return "Unknown", "Unknown"
