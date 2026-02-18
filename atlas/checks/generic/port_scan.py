"""
Port Scan Check

Scans for open ports using nmap (if available) or internal fallback.
"""

import asyncio
import shutil
import subprocess
import socket
from typing import Dict, Any, List

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class PortScanCheck(VulnerabilityCheck):
    """
    Check for open ports.
    Uses nmap if installed, otherwise falls back to python sockets.
    """

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="port_scan",
            name="Port Scanning",
            category="Network Security",
            severity=Severity.MEDIUM,
            description="Identifies open ports and running services.",
            owasp_category="A05:2021 Security Misconfiguration",
            cwe_id="CWE-200",
            tags=["nmap", "port-scan", "network"]
        )

    # Top 20 common ports for fallback
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 
        443, 445, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 27017
    ]

    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        nmap_path = shutil.which("nmap")
        
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        if nmap_path:
            return await self._run_nmap(nmap_path, hostname)
        else:
            return await self._run_fallback(hostname)
            
    async def _run_nmap(self, tool_path: str, hostname: str) -> CheckResult:
        """Run nmap fast scan"""
        logger.info(f"Running nmap on {hostname}")
        
        try:
            # nmap -F <hostname> (Fast scan, top 100 ports)
            process = await asyncio.create_subprocess_exec(
                tool_path, "-F", hostname,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            open_ports = []
            if stdout:
                output = stdout.decode()
                for line in output.splitlines():
                    if "/tcp" in line and "open" in line:
                        open_ports.append(line.strip())
            
            if open_ports:
                return self._vulnerable(
                    title="Open Ports Discovered (Nmap)",
                    description=f"Found {len(open_ports)} open ports using Nmap.",
                    evidence="\n".join(open_ports),
                    remediation="Ensure only necessary ports are open. Use a firewall to restrict access.",
                    severity=Severity.INFO if len(open_ports) < 5 else Severity.LOW
                )
                
        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")
            return await self._run_fallback(hostname)
            
        return self._not_vulnerable()

    async def _run_fallback(self, hostname: str) -> CheckResult:
        """Fallback implementation using python sockets"""
        logger.info(f"Running port scan check (Fallback) on {hostname}")
        
        open_ports = []
        
        for port in self.COMMON_PORTS:
            try:
                # Use asyncio for non-blocking connect
                _, writer = await asyncio.open_connection(hostname, port)
                open_ports.append(f"{port}/tcp open")
                writer.close()
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass
            except Exception as e:
                logger.debug(f"Port scan error {port}: {e}")
        
        if open_ports:
             return self._vulnerable(
                title="Open Ports Discovered",
                description=f"Found {len(open_ports)} open ports using Python socket scan.",
                evidence="\n".join(open_ports),
                remediation="Ensure only necessary ports are open.",
                severity=Severity.INFO
            )
            
        return self._not_vulnerable()
