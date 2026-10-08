"""Storage service — saves and retrieves analysis results as JSON files."""

import json
import os
from typing import Optional

from app.models.analysis import AnalysisResult
from app.utils.file_utils import get_results_dir


class StorageService:
    """Manages persistence of analysis results as JSON files."""

    def __init__(self, results_dir: Optional[str] = None):
        self.results_dir = results_dir or get_results_dir()
        os.makedirs(self.results_dir, exist_ok=True)

    def save(self, result: AnalysisResult) -> str:
        """
        Save an analysis result to a JSON file.

        Returns:
            Path to the saved JSON file.
        """
        filepath = os.path.join(
            self.results_dir, f"{result.analysis_id}.json"
        )
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, ensure_ascii=False)
        return filepath

    def load(self, analysis_id: str) -> Optional[AnalysisResult]:
        """
        Load a previously stored analysis result.

        Returns:
            AnalysisResult if found, None otherwise.
        """
        filepath = os.path.join(self.results_dir, f"{analysis_id}.json")
        if not os.path.isfile(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return AnalysisResult(**data)
        except (json.JSONDecodeError, Exception):
            return None

    def list_analyses(self) -> list[str]:
        """List all stored analysis IDs."""
        ids = []
        for fname in os.listdir(self.results_dir):
            if fname.endswith(".json"):
                ids.append(fname.replace(".json", ""))
        return sorted(ids)

    def delete(self, analysis_id: str) -> bool:
        """Delete a stored analysis result."""
        filepath = os.path.join(self.results_dir, f"{analysis_id}.json")
        if os.path.isfile(filepath):
            os.remove(filepath)
            return True
        return False
