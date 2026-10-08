"""Bandit analyzer — runs Bandit for Python security analysis."""

import json
import subprocess
import sys
import os
from typing import Optional

from app.models.finding import Finding, FindingType, Severity

# Mapping Bandit severity to normalized Severity
BANDIT_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}

# Mapping Bandit confidence to string
BANDIT_CONFIDENCE_MAP: dict[str, str] = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


class BanditAnalyzer:
    """Run Bandit on Python source files and normalize findings."""

    def analyze(self, file_path: str, base_dir: Optional[str] = None) -> list[Finding]:
        """
        Analyze a Python file with Bandit for security issues.

        Args:
            file_path: Absolute path to the Python file.
            base_dir: Base directory for relative path reporting.

        Returns:
            List of normalized security findings.
        """
        findings: list[Finding] = []

        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "bandit",
                    "-f", "json",
                    "-ll",  # Report medium and higher severity
                    file_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            output = result.stdout.strip()
            if not output:
                return findings

            try:
                bandit_output = json.loads(output)
            except json.JSONDecodeError:
                return findings

            results = bandit_output.get("results", [])
            relative_file = os.path.basename(file_path)
            if base_dir:
                try:
                    relative_file = os.path.relpath(file_path, base_dir)
                except ValueError:
                    relative_file = os.path.basename(file_path)

            for idx, item in enumerate(results):
                original_severity = item.get("issue_severity", "MEDIUM")
                confidence = item.get("issue_confidence", "MEDIUM")

                finding = Finding(
                    id=f"bandit_{relative_file}_{idx + 1}",
                    source="Bandit",
                    type=FindingType.SECURITY_VULNERABILITY,
                    severity=BANDIT_SEVERITY_MAP.get(
                        original_severity, Severity.MEDIUM
                    ),
                    original_severity=original_severity,
                    rule=item.get("test_id", "unknown"),
                    message=item.get("issue_text", "Security issue detected"),
                    file=relative_file,
                    line=item.get("line_number", 0),
                    column=item.get("col_offset", 0),
                    end_line=item.get("end_col_offset"),
                    confidence=BANDIT_CONFIDENCE_MAP.get(confidence, confidence),
                    category=item.get("test_name"),
                    evidence=item.get("code", None),
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            findings.append(Finding(
                id="bandit_timeout",
                source="Bandit",
                type=FindingType.SECURITY_VULNERABILITY,
                severity=Severity.INFO,
                rule="timeout",
                message="Bandit analysis timed out",
                file=os.path.basename(file_path),
                line=0,
            ))
        except FileNotFoundError:
            findings.append(Finding(
                id="bandit_not_found",
                source="Bandit",
                type=FindingType.SECURITY_VULNERABILITY,
                severity=Severity.INFO,
                rule="tool-not-found",
                message="Bandit is not installed or not found in PATH",
                file=os.path.basename(file_path),
                line=0,
            ))
        except Exception as e:
            findings.append(Finding(
                id="bandit_error",
                source="Bandit",
                type=FindingType.SECURITY_VULNERABILITY,
                severity=Severity.INFO,
                rule="analysis-error",
                message=f"Bandit analysis failed: {str(e)}",
                file=os.path.basename(file_path),
                line=0,
            ))

        return findings
