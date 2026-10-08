"""Input/output driver for the risk-adaptive prioritization pipeline."""

import json
import sys
from collections.abc import Mapping
from typing import Any

import pandas as pd

from core.deduplicator import Deduplicator
from core.normalizer import InputNormalizer
from core.risk_calculator import RiskAdaptiveCalculator
from utils.logger import get_logger

LOGGER = get_logger(__name__)
OUTPUT_COLUMNS = [
    "finding_id",
    "rule_id",
    "title",
    "file_path",
    "line_number",
    "severity",
    "confidence",
    "calculated_risk_score",
    "risk_category",
    "contributing_agents",
]


def run_prioritization_pipeline(raw_json_input: str) -> str:
    """Validate, deduplicate, score, and return findings as JSON records."""
    parsed: Any = json.loads(raw_json_input)
    if not isinstance(parsed, list):
        raise ValueError("Input JSON must be an array of finding objects")
    if any(not isinstance(item, Mapping) for item in parsed):
        raise ValueError("Every finding in the input array must be a JSON object")

    findings = InputNormalizer().process(parsed)
    deduped_findings = Deduplicator().process(findings)
    calculator = RiskAdaptiveCalculator()
    scored = calculator.compute_risk_score(pd.DataFrame(deduped_findings))
    ranked = calculator.rank_and_format(scored)

    if ranked.empty:
        return "[]"

    output = ranked[OUTPUT_COLUMNS]
    return output.to_json(orient="records", indent=2, force_ascii=False)


def main() -> int:
    raw_input = sys.stdin.read()
    try:
        print(run_prioritization_pipeline(raw_input))
    except (json.JSONDecodeError, ValueError) as exc:
        LOGGER.error("Could not process findings: %s", exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
