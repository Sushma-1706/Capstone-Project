"""Deterministic, location-aware deduplication of analyzer findings."""

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from typing import Any


class Deduplicator:
    """Merge reports for the same rule at the same source location."""

    @staticmethod
    def generate_fingerprint(finding: Mapping[str, Any]) -> str:
        raw_key = json.dumps(
            [
                finding["file_path"],
                finding["line_number"],
                finding["rule_id"],
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def process(self, raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in raw_findings:
            grouped[self.generate_fingerprint(finding)].append(finding)

        deduped: list[dict[str, Any]] = []
        for fingerprint, group in grouped.items():
            primary = max(
                group,
                key=lambda finding: (
                    finding["confidence"],
                    finding["title"],
                    finding["agent_id"],
                ),
            )
            merged = dict(primary)
            merged["finding_id"] = fingerprint
            merged["contributing_agents"] = sorted(
                {finding["agent_id"] for finding in group}
            )
            for metric in (
                "confidence",
                "security_impact",
                "code_impact",
                "exploitability",
            ):
                merged[metric] = max(finding[metric] for finding in group)
            deduped.append(merged)

        return deduped
