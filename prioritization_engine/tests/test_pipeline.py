"""Focused tests for validation, deduplication, scoring, and output."""

import json
import unittest

import pandas as pd
from pydantic import ValidationError

from core.deduplicator import Deduplicator
from core.normalizer import InputNormalizer
from core.risk_calculator import RiskAdaptiveCalculator
from main import run_prioritization_pipeline


def make_finding(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "agent_id": "scanner",
        "rule_id": "SEC001",
        "title": "Unsafe query",
        "file_path": "src/db.py",
        "line_number": 12,
        "severity": "HIGH",
        "confidence": 0.8,
        "security_impact": 8.0,
        "code_impact": 5.0,
        "exploitability": 7.0,
    }
    finding.update(overrides)
    return finding


class NormalizerTests(unittest.TestCase):
    def test_applies_defaults_and_preserves_metadata(self) -> None:
        finding = make_finding()
        del finding["code_impact"]
        finding["metadata"] = {"source": "test"}

        result = InputNormalizer().process([finding])[0]

        self.assertEqual(result["code_impact"], 1.0)
        self.assertEqual(result["metadata"], {"source": "test"})

    def test_invalid_values_report_finding_index(self) -> None:
        with self.assertRaisesRegex(ValueError, "index 0"):
            InputNormalizer().process([make_finding(confidence=1.1)])

    def test_line_number_must_be_positive(self) -> None:
        with self.assertRaises(ValidationError):
            from models.schema import RawFinding

            RawFinding.model_validate(make_finding(line_number=0))


class DeduplicatorTests(unittest.TestCase):
    def test_merges_metrics_and_sorts_agent_ids_without_mutating_inputs(self) -> None:
        first = make_finding(agent_id="z-agent", confidence=0.7, code_impact=3.0)
        second = make_finding(
            agent_id="a-agent",
            title="More specific title",
            confidence=0.9,
            security_impact=9.0,
            code_impact=8.0,
            exploitability=9.0,
        )
        original_first = first.copy()

        result = Deduplicator().process([first, second])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["title"], "More specific title")
        self.assertEqual(result[0]["contributing_agents"], ["a-agent", "z-agent"])
        self.assertEqual(result[0]["code_impact"], 8.0)
        self.assertEqual(first, original_first)

    def test_same_rule_at_different_locations_is_not_merged(self) -> None:
        result = Deduplicator().process(
            [make_finding(), make_finding(line_number=13)]
        )
        self.assertEqual(len(result), 2)


class RiskCalculatorTests(unittest.TestCase):
    def test_computes_expected_score_and_does_not_mutate_input(self) -> None:
        source = pd.DataFrame([make_finding()])
        original_columns = list(source.columns)

        result = RiskAdaptiveCalculator().compute_risk_score(source)

        self.assertEqual(result.loc[0, "calculated_risk_score"], 7.45)
        self.assertEqual(result.loc[0, "risk_category"], "HIGH")
        self.assertEqual(list(source.columns), original_columns)

    def test_classifies_exact_thresholds(self) -> None:
        calculator = RiskAdaptiveCalculator()
        self.assertEqual(calculator._classify_risk(8.5), "CRITICAL")
        self.assertEqual(calculator._classify_risk(6.5), "HIGH")
        self.assertEqual(calculator._classify_risk(4.0), "MEDIUM")
        self.assertEqual(calculator._classify_risk(3.99), "LOW")

    def test_empty_input_stays_empty(self) -> None:
        calculator = RiskAdaptiveCalculator()
        empty = pd.DataFrame()
        self.assertTrue(calculator.rank_and_format(calculator.compute_risk_score(empty)).empty)


class PipelineTests(unittest.TestCase):
    def test_pipeline_deduplicates_and_emits_stable_json(self) -> None:
        payload = json.dumps(
            [
                make_finding(agent_id="z-agent", confidence=0.8),
                make_finding(agent_id="a-agent", confidence=0.9),
            ]
        )

        output = run_prioritization_pipeline(payload)
        result = json.loads(output)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["contributing_agents"], ["a-agent", "z-agent"])
        self.assertEqual(result[0]["severity"], "HIGH")
        self.assertEqual(result[0]["risk_category"], "HIGH")

    def test_pipeline_accepts_empty_array(self) -> None:
        self.assertEqual(run_prioritization_pipeline("[]"), "[]")

    def test_pipeline_rejects_non_array_json(self) -> None:
        with self.assertRaisesRegex(ValueError, "array"):
            run_prioritization_pipeline("{}")


if __name__ == "__main__":
    unittest.main()
