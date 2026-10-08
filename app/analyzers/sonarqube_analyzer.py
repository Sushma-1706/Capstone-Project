"""SonarQube analyzer — optional integration for additional static analysis."""

import os
import subprocess
import sys
from typing import Optional

import requests

from app.models.finding import Finding, FindingType, Severity

# Mapping SonarQube types to normalized FindingType
SONAR_TYPE_MAP: dict[str, FindingType] = {
    "BUG": FindingType.BUG,
    "VULNERABILITY": FindingType.SECURITY_VULNERABILITY,
    "CODE_SMELL": FindingType.CODE_SMELL,
    "SECURITY_HOTSPOT": FindingType.SECURITY_VULNERABILITY,
}

# Mapping SonarQube severity to normalized Severity
SONAR_SEVERITY_MAP: dict[str, Severity] = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.CRITICAL,
    "MAJOR": Severity.HIGH,
    "MINOR": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SonarQubeAnalyzer:
    """Optional SonarQube integration for additional static-analysis evidence."""

    def __init__(
        self,
        sonar_url: str = "http://localhost:9000",
        sonar_token: Optional[str] = None,
    ):
        self.sonar_url = sonar_url.rstrip("/")
        self.sonar_token = sonar_token
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check whether SonarQube server is reachable."""
        if self._available is not None:
            return self._available
        try:
            resp = requests.get(
                f"{self.sonar_url}/api/system/status",
                timeout=5,
                auth=(self.sonar_token, "") if self.sonar_token else None,
            )
            self._available = resp.status_code == 200
        except Exception:
            self._available = False
        return self._available

    def analyze(
        self,
        project_dir: str,
        project_key: Optional[str] = None,
        base_dir: Optional[str] = None,
    ) -> list[Finding]:
        """
        Run SonarScanner on a project directory and retrieve findings.

        Args:
            project_dir: Directory containing source files.
            project_key: SonarQube project key. Auto-generated if not provided.
            base_dir: Base directory for relative path reporting.

        Returns:
            List of normalized findings from SonarQube.
        """
        if not self.is_available():
            return []

        project_key = project_key or f"sa_engine_{os.path.basename(project_dir)}"

        # Attempt to run SonarScanner
        scan_success = self._run_scanner(project_dir, project_key)
        if not scan_success:
            return []

        # Retrieve issues from SonarQube API
        return self._fetch_issues(project_key, base_dir)

    def _run_scanner(self, project_dir: str, project_key: str) -> bool:
        """Run sonar-scanner CLI on the project directory."""
        try:
            cmd = [
                "sonar-scanner",
                f"-Dsonar.projectKey={project_key}",
                f"-Dsonar.sources={project_dir}",
                f"-Dsonar.host.url={self.sonar_url}",
            ]
            if self.sonar_token:
                cmd.append(f"-Dsonar.login={self.sonar_token}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=project_dir,
            )
            return result.returncode == 0

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    def _fetch_issues(
        self, project_key: str, base_dir: Optional[str] = None
    ) -> list[Finding]:
        """Fetch issues from SonarQube API for a given project."""
        findings: list[Finding] = []
        page = 1
        page_size = 100

        try:
            while True:
                resp = requests.get(
                    f"{self.sonar_url}/api/issues/search",
                    params={
                        "componentKeys": project_key,
                        "ps": page_size,
                        "p": page,
                        "resolved": "false",
                    },
                    timeout=30,
                    auth=(self.sonar_token, "") if self.sonar_token else None,
                )

                if resp.status_code != 200:
                    break

                data = resp.json()
                issues = data.get("issues", [])
                if not issues:
                    break

                for idx, issue in enumerate(issues):
                    component = issue.get("component", "")
                    # Extract filename from component key
                    file_name = component.split(":")[-1] if ":" in component else component

                    original_severity = issue.get("severity", "MINOR")
                    original_type = issue.get("type", "CODE_SMELL")

                    finding = Finding(
                        id=f"sonar_{project_key}_{page}_{idx + 1}",
                        source="SonarQube",
                        type=SONAR_TYPE_MAP.get(
                            original_type, FindingType.CODE_SMELL
                        ),
                        severity=SONAR_SEVERITY_MAP.get(
                            original_severity, Severity.MEDIUM
                        ),
                        original_severity=original_severity,
                        rule=issue.get("rule", "unknown"),
                        message=issue.get("message", "Issue detected by SonarQube"),
                        file=file_name,
                        line=issue.get("line", 0),
                        column=issue.get("textRange", {}).get("startOffset", 0),
                        end_line=issue.get("textRange", {}).get("endLine"),
                        end_column=issue.get("textRange", {}).get("endOffset"),
                        category=original_type,
                        evidence=issue.get("message"),
                    )
                    findings.append(finding)

                total = data.get("total", 0)
                if page * page_size >= total:
                    break
                page += 1

        except Exception:
            pass

        return findings
