"""Pylint analyzer — runs Pylint programmatically and normalizes findings."""

import json
import subprocess
import sys
import tempfile
import os
from typing import Optional

from app.models.finding import Finding, FindingType, Severity

# Mapping Pylint message types to normalized FindingType
PYLINT_TYPE_MAP: dict[str, FindingType] = {
    "convention": FindingType.CODING_STANDARD,
    "refactor": FindingType.CODE_SMELL,
    "warning": FindingType.BUG,
    "error": FindingType.BUG,
    "fatal": FindingType.BUG,
}

# Mapping Pylint message types to normalized Severity
PYLINT_SEVERITY_MAP: dict[str, Severity] = {
    "convention": Severity.LOW,
    "refactor": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "error": Severity.HIGH,
    "fatal": Severity.CRITICAL,
}


class PylintAnalyzer:
    """Run Pylint on Python source files and normalize findings."""

    def analyze(self, file_path: str, base_dir: Optional[str] = None) -> list[Finding]:
        """
        Analyze a Python file with Pylint.

        Args:
            file_path: Absolute path to the Python file.
            base_dir: Base directory for relative path reporting.

        Returns:
            List of normalized findings.
        """
        findings: list[Finding] = []

        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "pylint",
                    "--output-format=json",
                    "--disable=C0114,C0115,C0116",  # Disable missing docstrings for cleaner output
                    file_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=base_dir or os.path.dirname(file_path),
            )

            # Pylint returns non-zero exit codes for findings (not just errors)
            output = result.stdout.strip()
            if not output:
                return findings

            try:
                pylint_results = json.loads(output)
            except json.JSONDecodeError:
                return findings

            relative_file = os.path.basename(file_path)
            if base_dir:
                try:
                    relative_file = os.path.relpath(file_path, base_dir)
                except ValueError:
                    relative_file = os.path.basename(file_path)

            for idx, item in enumerate(pylint_results):
                msg_type = item.get("type", "convention").lower()
                finding = Finding(
                    id=f"pylint_{relative_file}_{idx + 1}",
                    source="Pylint",
                    type=PYLINT_TYPE_MAP.get(msg_type, FindingType.CODE_SMELL),
                    severity=PYLINT_SEVERITY_MAP.get(msg_type, Severity.MEDIUM),
                    original_severity=msg_type,
                    rule=item.get("message-id", item.get("symbol", "unknown")),
                    message=item.get("message", "No message"),
                    file=relative_file,
                    line=item.get("line", 0),
                    column=item.get("column", 0),
                    end_line=item.get("endLine"),
                    end_column=item.get("endColumn"),
                    category=item.get("symbol"),
                    evidence=item.get("message", None),
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            findings.append(Finding(
                id="pylint_timeout",
                source="Pylint",
                type=FindingType.BUG,
                severity=Severity.INFO,
                rule="timeout",
                message="Pylint analysis timed out",
                file=os.path.basename(file_path),
                line=0,
            ))
        except FileNotFoundError:
            findings.append(Finding(
                id="pylint_not_found",
                source="Pylint",
                type=FindingType.BUG,
                severity=Severity.INFO,
                rule="tool-not-found",
                message="Pylint is not installed or not found in PATH",
                file=os.path.basename(file_path),
                line=0,
            ))
        except Exception as e:
            findings.append(Finding(
                id="pylint_error",
                source="Pylint",
                type=FindingType.BUG,
                severity=Severity.INFO,
                rule="analysis-error",
                message=f"Pylint analysis failed: {str(e)}",
                file=os.path.basename(file_path),
                line=0,
            ))

        return findings
