"""Pydantic models for individual findings."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class FindingType(str, Enum):
    """Normalized finding categories."""
    BUG = "BUG"
    CODE_SMELL = "CODE_SMELL"
    SECURITY_VULNERABILITY = "SECURITY_VULNERABILITY"
    COMPLEXITY = "COMPLEXITY"
    CODING_STANDARD = "CODING_STANDARD"
    SYNTAX_ERROR = "SYNTAX_ERROR"


class Severity(str, Enum):
    """Normalized severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AnalysisSource(str, Enum):
    """Source tools that can produce findings."""
    AST = "AST"
    PYLINT = "Pylint"
    BANDIT = "Bandit"
    RADON = "Radon"
    SONARQUBE = "SonarQube"


class Finding(BaseModel):
    """A single normalized finding from any analysis tool."""
    id: str = Field(..., description="Unique finding identifier")
    source: str = Field(..., description="Tool that generated this finding")
    type: FindingType = Field(..., description="Normalized finding category")
    severity: Severity = Field(..., description="Normalized severity level")
    rule: str = Field(..., description="Rule or check ID from the source tool")
    message: str = Field(..., description="Human-readable description of the issue")
    file: str = Field(..., description="File where the issue was found")
    line: int = Field(..., description="Line number of the issue")
    column: Optional[int] = Field(None, description="Column number of the issue")
    end_line: Optional[int] = Field(None, description="End line number")
    end_column: Optional[int] = Field(None, description="End column number")
    confidence: Optional[str] = Field(None, description="Confidence level from the tool")
    category: Optional[str] = Field(None, description="Sub-category from the tool")
    original_severity: Optional[str] = Field(
        None, description="Original severity from the source tool"
    )
    evidence: Optional[str] = Field(
        None, description="Supporting evidence or code snippet"
    )


class ComplexityFunction(BaseModel):
    """Complexity info for a single function or method."""
    name: str
    complexity: int
    rank: str
    line: Optional[int] = None
    col_offset: Optional[int] = None
    end_line: Optional[int] = None
    classname: Optional[str] = None


class ComplexityResult(BaseModel):
    """Aggregated complexity results."""
    total_complexity: int = 0
    average_complexity: float = 0.0
    functions: list[ComplexityFunction] = []
    maintainability_index: Optional[float] = None
    raw_metrics: Optional[dict] = None
