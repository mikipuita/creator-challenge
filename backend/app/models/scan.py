"""Pydantic models representing scan requests, findings, and results."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from app.models.report import FullReport


class Severity(str, Enum):
    """Supported severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModuleStatus(str, Enum):
    """Lifecycle states for an individual scan module."""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETE = "complete"
    ERROR = "error"
    SKIPPED = "skipped"


class ScanLifecycle(str, Enum):
    """Lifecycle states for an entire scan."""

    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    """Input payload for kicking off a new domain scan."""

    domain: str = Field(..., min_length=3, max_length=253)


class Finding(BaseModel):
    """A single security observation produced by a scan module."""

    title: str = Field(..., min_length=3)
    category: str = Field(..., min_length=2)
    severity: Severity
    description: str = Field(..., min_length=10)
    impact: str = Field(..., min_length=10)
    remediation: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class CategoryScore(BaseModel):
    """The score details for a single weighted category."""

    name: str = Field(..., min_length=2)
    score: float = Field(..., ge=0, le=100)
    weight: float = Field(..., ge=0, le=100)
    findings_count: int = Field(default=0, ge=0)


class RiskScore(BaseModel):
    """Weighted roll-up of category-level scores into an overall grade."""

    overall_grade: Literal["A", "B", "C", "D", "F"]
    overall_score: float = Field(..., ge=0, le=100)
    category_scores: List[CategoryScore] = Field(default_factory=list)
    critical_findings_count: int = Field(default=0, ge=0)
    high_findings_count: int = Field(default=0, ge=0)


class ModuleResult(BaseModel):
    """Output of a scan module, including findings and raw structured data."""

    name: str = Field(..., min_length=2)
    status: ModuleStatus = ModuleStatus.PENDING
    findings: List[Finding] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict)
    note: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanResult(BaseModel):
    """The persisted result object returned by the scan/results/report APIs."""

    scan_id: str
    domain: str
    status: ScanLifecycle = ScanLifecycle.SCANNING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    modules: Dict[str, ModuleResult] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    report: Optional[FullReport] = None
