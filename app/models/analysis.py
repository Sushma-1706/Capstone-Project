"""Pydantic models for analysis requests and responses."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from app.models.finding import Finding, ComplexityResult


class AnalysisStatus(str, Enum):
    """Status of an analysis run."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ToolStatus(str, Enum):
    """Status of a specific tool within an analysis."""
    SUCCESS = "success"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


class AnalysisSummary(BaseModel):
    """Summary counts of findings by category."""
    total_findings: int = 0
    bugs: int = 0
    code_smells: int = 0
    security_vulnerabilities: int = 0
    complexity_issues: int = 0
    coding_standard_violations: int = 0
    syntax_errors: int = 0


class FileInfo(BaseModel):
    """Info about a parsed file."""
    filename: str
    language: str = "python"
    lines: int = 0
    classes: list[str] = []
    functions: list[str] = []
    imports: list[str] = []
    has_syntax_errors: bool = False
    syntax_error_message: Optional[str] = None


class ToolReport(BaseModel):
    """Status report for each tool in the analysis."""
    status: ToolStatus
    message: Optional[str] = None
    findings_count: int = 0


class AnalysisResult(BaseModel):
    """Complete analysis result for an analysis run."""
    analysis_id: str = Field(..., description="Unique analysis identifier")
    status: AnalysisStatus = Field(default=AnalysisStatus.PENDING)
    summary: AnalysisSummary = Field(default_factory=AnalysisSummary)
    findings: list[Finding] = []
    complexity: Optional[ComplexityResult] = None
    files_analyzed: list[FileInfo] = []
    tools_used: list[str] = []
    tool_reports: dict[str, ToolReport] = {}
    errors: list[str] = []
    timestamp: Optional[str] = None

    def compute_summary(self) -> None:
        """Compute the summary from the findings list."""
        self.summary = AnalysisSummary(total_findings=len(self.findings))
        for f in self.findings:
            ftype = f.type.value
            if ftype == "BUG":
                self.summary.bugs += 1
            elif ftype == "CODE_SMELL":
                self.summary.code_smells += 1
            elif ftype == "SECURITY_VULNERABILITY":
                self.summary.security_vulnerabilities += 1
            elif ftype == "COMPLEXITY":
                self.summary.complexity_issues += 1
            elif ftype == "CODING_STANDARD":
                self.summary.coding_standard_violations += 1
            elif ftype == "SYNTAX_ERROR":
                self.summary.syntax_errors += 1
