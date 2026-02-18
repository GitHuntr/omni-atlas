"""
Misconfiguration Check

Checks for missing security headers and other common misconfigurations.
"""

import httpx
from typing import Dict, Any, List

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class MisconfigurationCheck(VulnerabilityCheck):
    """
    Check for security misconfigurations (headers, exposed info).
    """

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="misconfiguration",
            name="Security Misconfiguration",
            category="Security Misconfiguration",
            severity=Severity.MEDIUM,
            description="Checks for missing security headers and disclosed server information.",
            owasp_category="A05:2021 Security Misconfiguration",
            cwe_id="CWE-16",
            tags=["headers", "config", "passive"]
        )

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": "Missing HSTS header (enforce HTTPS)",
        "X-Frame-Options": "Missing X-Frame-Options (clickjacking protection)",
        "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing protection)",
        "Content-Security-Policy": "Missing Content-Security-Policy (XSS mitigation)"
    }

    DISCLOSURE_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version"
    ]

    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(target)
                headers = response.headers
                
                issues = []
                
                # Check missing headers
                for header, msg in self.REQUIRED_HEADERS.items():
                    if header not in headers:
                        issues.append(msg)
                        
                # Check information disclosure
                for header in self.DISCLOSURE_HEADERS:
                    if header in headers:
                        issues.append(f"Exposed server information: {header}: {headers[header]}")
                
                if issues:
                    return self._vulnerable(
                        title="Security Headers Missing / Information Disclosure",
                        description=f"Found {len(issues)} configuration issues.",
                        evidence="\n".join(issues),
                        remediation="Configure web server to send security headers and hide version information.",
                        severity=Severity.LOW if len(issues) < 3 else Severity.MEDIUM
                    )
                    
                return self._not_vulnerable()

        except Exception as e:
            logger.error(f"Misconfiguration check failed: {e}")
            return self._error(str(e))
