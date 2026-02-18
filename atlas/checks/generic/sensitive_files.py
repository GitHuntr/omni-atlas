"""
Sensitive Files Check

Checks for exposed sensitive files using gobuster (if available) or internal fallback.
"""

import asyncio
import shutil
import subprocess
import json
from typing import Dict, Any, List
import httpx

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class SensitiveFilesCheck(VulnerabilityCheck):
    """
    Check for sensitive files (backups, config, git, etc).
    Uses gobuster if installed, otherwise falls back to python requests.
    """

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="sensitive_files",
            name="Sensitive Files Exposure",
            category="Information Disclosure",
            severity=Severity.HIGH,
            description="Detects exposed sensitive files like configuration backups, .git directories, and environment files.",
            owasp_category="A05:2021 Security Misconfiguration",
            cwe_id="CWE-200",
            tags=["gobuster", "recon", "sensitive-files"]
        )

    COMMON_FILES = [
        ".env", ".git/HEAD", ".svn/entries", ".DS_Store",
        "config.php.bak", "web.config", "backup.sql",
        "id_rsa", "id_rsa.pub", "server.key",
        "wp-config.php", "composer.json", "package.json"
    ]

    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        gobuster_path = shutil.which("gobuster")
        metadata = context.get("metadata", {})
        wordlist = metadata.get("wordlist")
        
        # Only run gobuster if we have a wordlist (per user request)
        if gobuster_path and wordlist:
            return await self._run_gobuster(gobuster_path, target, wordlist)
        elif gobuster_path and not wordlist:
            logger.info("Gobuster available but no wordlist provided. Skipping tool execution.")
            return await self._run_fallback(target)
        else:
            return await self._run_fallback(target)
            
    async def _run_gobuster(self, tool_path: str, target: str, wordlist: str) -> CheckResult:
        """Run gobuster dir mode"""
        logger.info(f"Running gobuster on {target} with wordlist {wordlist}")
        
        found_files = []
        
        try:
            # Run gobuster
            # gobuster dir -u <target> -w <wordlist> -n -q --no-error
            process = await asyncio.create_subprocess_exec(
                tool_path, "dir",
                "-u", target,
                "-w", wordlist,
                "-n", "-q", "--no-error",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                output = stdout.decode()
                for line in output.splitlines():
                    # Gobuster output format usually: /path (Status: 200) [Size: 123]
                    if "Status: 200" in line or "Status: 301" in line:
                         found_files.append(line.strip())
                         
            if found_files:
                return self._vulnerable(
                    title="Sensitive Files Discovered (Gobuster)",
                    description=f"Found {len(found_files)} sensitive files using Gobuster with custom wordlist.",
                    evidence="\n".join(found_files),
                    remediation="Remove sensitive files from the web root.",
                    severity=Severity.HIGH
                )

        except Exception as e:
            logger.error(f"Gobuster execution failed: {e}")
            # Fallback if tool execution fails
            return await self._run_fallback(target)
            
        return self._not_vulnerable()

    async def _run_fallback(self, target: str) -> CheckResult:
        """Fallback implementation using httpx"""
        logger.info("Running sensitive files check (Fallback)")
        
        found_files = []
        
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for file_path in self.COMMON_FILES:
                url = f"{target.rstrip('/')}/{file_path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        # Simple heuristics to avoid false positives (custom 404s returning 200)
                        if len(resp.content) > 0 and "404" not in resp.text:
                            found_files.append(url)
                except Exception:
                    pass
        
        if found_files:
             return self._vulnerable(
                title="Sensitive Files Discovered",
                description=f"Found {len(found_files)} sensitive files using Python fallback.",
                evidence="\n".join(found_files),
                remediation="Remove sensitive files from public access.",
                severity=Severity.HIGH
            )
            
        return self._not_vulnerable()
