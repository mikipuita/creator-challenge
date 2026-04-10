"""Risk scoring logic for DomainVitals scan results."""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List

from app.models.scan import CategoryScore, Finding, ModuleResult, RiskScore, Severity

CATEGORY_WEIGHTS: Dict[str, float] = {
    "email_security": 25.0,
    "ssl_tls": 20.0,
    "headers": 20.0,
    "open_ports": 15.0,
    "dns": 10.0,
    "tech_stack": 10.0,
}

SEVERITY_PENALTIES = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 25,
    Severity.MEDIUM: 12,
    Severity.LOW: 5,
    Severity.INFO: 1,
}

MODULE_TO_CATEGORY = {
    "dns": "dns",
    "subdomains": "dns",
    "ssl_tls": "ssl_tls",
    "email_security": "email_security",
    "headers": "headers",
    "open_ports": "open_ports",
    "tech_stack": "tech_stack",
}


def _score_findings(findings: Iterable[Finding]) -> float:
    """Convert a set of findings into a 0-100 category score."""

    deductions = sum(SEVERITY_PENALTIES[finding.severity] for finding in findings)
    return max(0.0, min(100.0, 100.0 - float(deductions)))


def calculate_risk_score(modules: Dict[str, ModuleResult]) -> RiskScore:
    """Build weighted category scores and the overall report card."""

    categorized_findings: Dict[str, List[Finding]] = {name: [] for name in CATEGORY_WEIGHTS}
    all_findings: List[Finding] = []
    for module_name, module_result in modules.items():
        category_name = MODULE_TO_CATEGORY.get(module_name)
        if not category_name:
            continue
        categorized_findings[category_name].extend(module_result.findings)
        all_findings.extend(module_result.findings)

    category_scores: List[CategoryScore] = []
    weighted_total = 0.0
    total_weight = sum(CATEGORY_WEIGHTS.values())
    for category_name, weight in CATEGORY_WEIGHTS.items():
        findings = categorized_findings.get(category_name, [])
        score = _score_findings(findings)
        category_scores.append(
            CategoryScore(
                name=category_name,
                score=round(score, 2),
                weight=weight,
                findings_count=len(findings),
            )
        )
        weighted_total += score * (weight / 100.0)

    overall_score = round(weighted_total / (total_weight / 100.0), 2)
    if overall_score >= 90:
        grade = "A"
    elif overall_score >= 80:
        grade = "B"
    elif overall_score >= 70:
        grade = "C"
    elif overall_score >= 60:
        grade = "D"
    else:
        grade = "F"

    severity_counts = Counter(finding.severity for finding in all_findings)
    return RiskScore(
        overall_grade=grade,
        overall_score=overall_score,
        category_scores=category_scores,
        critical_findings_count=severity_counts[Severity.CRITICAL],
        high_findings_count=severity_counts[Severity.HIGH],
    )
