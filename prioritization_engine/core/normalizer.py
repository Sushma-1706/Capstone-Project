"""Validation and normalization for incoming analyzer findings."""

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import ValidationError

from models.schema import RawFinding


class InputNormalizer:
    """Convert input mappings into validated, consistently formatted findings."""

    def process(self, raw_findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for index, raw_finding in enumerate(raw_findings):
            try:
                finding = RawFinding.model_validate(raw_finding)
            except ValidationError as exc:
                raise ValueError(f"Invalid finding at index {index}: {exc}") from exc

            normalized_finding = finding.model_dump()
            normalized_finding["severity"] = finding.severity.upper()
            normalized.append(normalized_finding)
        return normalized
