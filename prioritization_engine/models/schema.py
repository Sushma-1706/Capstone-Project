"""Pydantic models for raw and prioritized findings."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RawFinding(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    agent_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    severity: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    security_impact: float = Field(default=1.0, ge=1.0, le=10.0)
    code_impact: float = Field(default=1.0, ge=1.0, le=10.0)
    exploitability: float = Field(default=1.0, ge=1.0, le=10.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PrioritizedFinding(BaseModel):
    finding_id: str
    title: str
    file_path: str
    line_number: int
    raw_severity: str
    confidence: float
    calculated_risk_score: float
    risk_category: str
    contributing_agents: list[str]
