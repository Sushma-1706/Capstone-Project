"""Weighted risk scoring and deterministic ranking."""

import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


class RiskAdaptiveCalculator:
    def __init__(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            config_path = Path(__file__).resolve().parents[1] / "config" / "risk_weights.json"
        with Path(config_path).open(encoding="utf-8") as config_file:
            self.config: dict[str, Any] = json.load(config_file)

        self.weights = self.config["weights"]
        self.base_scores = self.config["severity_base_scores"]
        self.thresholds = self.config["risk_thresholds"]
        self._validate_config()

    def _validate_config(self) -> None:
        expected_weights = {
            "severity",
            "confidence",
            "security_impact",
            "code_impact",
            "exploitability",
        }
        if set(self.weights) != expected_weights:
            raise ValueError(f"weights must contain exactly {sorted(expected_weights)}")
        values = list(self.weights.values())
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("weights must be finite, non-negative numbers")
        if not math.isclose(sum(values), 1.0, abs_tol=1e-9):
            raise ValueError("weights must sum to 1.0")

        if not all(tier in self.thresholds for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")):
            raise ValueError("risk_thresholds must define CRITICAL, HIGH, MEDIUM, and LOW")
        if not (
            self.thresholds["CRITICAL"]
            >= self.thresholds["HIGH"]
            >= self.thresholds["MEDIUM"]
            >= self.thresholds["LOW"]
        ):
            raise ValueError("risk thresholds must be in descending tier order")

    def compute_risk_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a scored copy; do not mutate the caller's DataFrame."""
        if df.empty:
            return df.copy()

        scored = df.copy()
        scored["severity_score"] = (
            scored["severity"].astype(str).str.upper().map(self.base_scores).fillna(1.0)
        )
        scored["calculated_risk_score"] = (
            scored["severity_score"] * self.weights["severity"]
            + scored["confidence"] * 10.0 * self.weights["confidence"]
            + scored["security_impact"] * self.weights["security_impact"]
            + scored["code_impact"] * self.weights["code_impact"]
            + scored["exploitability"] * self.weights["exploitability"]
        )
        scored["calculated_risk_score"] = (
            np.clip(scored["calculated_risk_score"], 0.0, 10.0).round(2)
        )
        scored["risk_category"] = scored["calculated_risk_score"].map(self._classify_risk)
        return scored

    def _classify_risk(self, score: float) -> str:
        if score >= self.thresholds["CRITICAL"]:
            return "CRITICAL"
        if score >= self.thresholds["HIGH"]:
            return "HIGH"
        if score >= self.thresholds["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    def rank_and_format(self, df: pd.DataFrame) -> pd.DataFrame:
        """Sort by score, confidence, then fingerprint for stable output."""
        if df.empty:
            return df.copy()
        sort_columns = ["calculated_risk_score", "confidence"]
        ascending = [False, False]
        if "finding_id" in df.columns:
            sort_columns.append("finding_id")
            ascending.append(True)
        return df.sort_values(
            by=sort_columns, ascending=ascending, kind="mergesort"
        ).reset_index(drop=True)
