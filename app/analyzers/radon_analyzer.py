"""Radon analyzer — computes cyclomatic complexity and maintainability metrics."""

import json
import subprocess
import sys
import os
from typing import Optional

from app.models.finding import (
    ComplexityFunction,
    ComplexityResult,
    Finding,
    FindingType,
    Severity,
)

# Radon complexity rank to severity mapping
RANK_SEVERITY_MAP: dict[str, Severity] = {
    "A": Severity.INFO,      # 1-5:  simple
    "B": Severity.LOW,       # 6-10: well structured
    "C": Severity.MEDIUM,    # 11-20: slightly complex
    "D": Severity.HIGH,      # 21-30: more complex
    "E": Severity.HIGH,      # 31-40: complex
    "F": Severity.CRITICAL,  # 41+:  very complex
}


class RadonAnalyzer:
    """Run Radon on Python source files for complexity and maintainability metrics."""

    def analyze(
        self, file_path: str, base_dir: Optional[str] = None
    ) -> tuple[ComplexityResult, list[Finding]]:
        """
        Analyze a Python file with Radon.

        Args:
            file_path: Absolute path to the Python file.
            base_dir: Base directory for relative path reporting.

        Returns:
            Tuple of (ComplexityResult, list of complexity findings).
        """
        findings: list[Finding] = []
        complexity_result = ComplexityResult()

        relative_file = os.path.basename(file_path)
        if base_dir:
            try:
                relative_file = os.path.relpath(file_path, base_dir)
            except ValueError:
                relative_file = os.path.basename(file_path)

        # --- Cyclomatic complexity ---
        cc_functions = self._get_cyclomatic_complexity(file_path)
        if cc_functions:
            total = sum(f.complexity for f in cc_functions)
            avg = total / len(cc_functions) if cc_functions else 0.0
            complexity_result.total_complexity = total
            complexity_result.average_complexity = round(avg, 2)
            complexity_result.functions = cc_functions

            # Create findings for high-complexity functions (rank C or worse)
            for func in cc_functions:
                if func.rank >= "C":
                    findings.append(Finding(
                        id=f"radon_cc_{relative_file}_{func.name}",
                        source="Radon",
                        type=FindingType.COMPLEXITY,
                        severity=RANK_SEVERITY_MAP.get(func.rank, Severity.MEDIUM),
                        rule=f"cyclomatic-complexity-{func.rank}",
                        message=(
                            f"Function '{func.name}' has cyclomatic complexity "
                            f"{func.complexity} (rank {func.rank})"
                        ),
                        file=relative_file,
                        line=func.line or 0,
                        column=func.col_offset or 0,
                        category="cyclomatic_complexity",
                        evidence=f"complexity={func.complexity}, rank={func.rank}",
                    ))

        # --- Maintainability index ---
        mi = self._get_maintainability_index(file_path)
        if mi is not None:
            complexity_result.maintainability_index = round(mi, 2)

        # --- Raw metrics ---
        raw = self._get_raw_metrics(file_path)
        if raw:
            complexity_result.raw_metrics = raw

        return complexity_result, findings

    def _get_cyclomatic_complexity(self, file_path: str) -> list[ComplexityFunction]:
        """Run radon cc and parse results."""
        functions: list[ComplexityFunction] = []
        try:
            result = subprocess.run(
                [sys.executable, "-m", "radon", "cc", "-j", "-a", file_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout.strip()
            if not output:
                return functions

            data = json.loads(output)
            # radon returns {filepath: [blocks]}
            for _path, blocks in data.items():
                if isinstance(blocks, list):
                    for block in blocks:
                        functions.append(ComplexityFunction(
                            name=block.get("name", "unknown"),
                            complexity=block.get("complexity", 0),
                            rank=block.get("rank", "A"),
                            line=block.get("lineno"),
                            col_offset=block.get("col_offset"),
                            end_line=block.get("endline"),
                            classname=block.get("classname"),
                        ))

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass

        return functions

    def _get_maintainability_index(self, file_path: str) -> Optional[float]:
        """Run radon mi and parse the maintainability index."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "radon", "mi", "-j", file_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout.strip()
            if not output:
                return None

            data = json.loads(output)
            for _path, mi_value in data.items():
                if isinstance(mi_value, (int, float)):
                    return float(mi_value)

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass

        return None

    def _get_raw_metrics(self, file_path: str) -> Optional[dict]:
        """Run radon raw and parse raw code metrics."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "radon", "raw", "-j", file_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout.strip()
            if not output:
                return None

            data = json.loads(output)
            for _path, metrics in data.items():
                if isinstance(metrics, dict):
                    return metrics

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass

        return None
