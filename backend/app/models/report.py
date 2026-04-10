"""Pydantic models for AI-generated and exported security reports."""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class ActionItem(BaseModel):
    """A prioritized remediation recommendation for the scanned domain."""

    title: str = Field(..., min_length=3)
    category: str = Field(..., min_length=2)
    priority: Literal["critical", "high", "medium", "low"] = "medium"
    difficulty: Literal["Easy", "Medium", "Hard"] = "Medium"
    rationale: str = Field(..., min_length=10)
    steps: List[str] = Field(default_factory=list)


class ReportSection(BaseModel):
    """Narrative breakdown for a single security category."""

    title: str = Field(..., min_length=3)
    summary: str = Field(..., min_length=10)
    findings: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)


class FullReport(BaseModel):
    """The complete human-readable report returned by the AI reporter."""

    executive_summary: str = Field(..., min_length=20)
    attacker_narrative: str = Field(..., min_length=20)
    category_breakdowns: List[ReportSection] = Field(default_factory=list)
    prioritized_action_items: List[ActionItem] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    model: Optional[str] = None
    disclaimer: str = (
        "This report highlights likely exposure based on passive recon and should be"
        " reviewed by a qualified security professional before major remediation work."
    )
