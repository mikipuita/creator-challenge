"""AI-assisted report generation for DomainVitals."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.models.report import ActionItem, FullReport, ReportSection
from app.models.scan import Finding, ScanResult, Severity
from app.services.demo_mode import DEMO_DOMAIN, load_demo_report_fixture

SYSTEM_PROMPT = """
You are a cybersecurity analyst writing a security assessment for a small business owner who has zero technical background.

Your job is to turn structured scan data into a plain-English report that is:
- easy for a non-technical business owner to understand
- professional enough to share with a business partner or IT consultant
- actionable, with clear step-by-step remediation guidance
- engaging through an "attacker's perspective" narrative that is vivid but not alarmist

Core writing rules:
1. Never invent findings, risks, technologies, grades, or remediation details that are not supported by the provided scan results.
2. Always explain jargon in parentheses the first time it appears.
   Example: "DMARC (an email rule that tells inbox providers what to do with fake messages)"
3. Use a real-world analogy for every technical concept you explain.
   Example: "No DMARC is like leaving your company mailbox unlocked so anyone can drop in mail that looks official."
4. Write in calm, confident language. Be informative, not theatrical or fearmongering.
5. If a category has no issues, still include it with a positive note.
6. Every finding must include:
   - a plain-English explanation
   - the likely business impact if ignored
   - step-by-step remediation instructions
   - a difficulty rating of easy, medium, or hard
7. Use only these severity values: critical, high, medium, low, info.
8. Use only these difficulty values: easy, medium, hard.
9. Sort action_items by priority ascending so 1 is the most urgent item.
10. Keep the entire response under 3000 tokens.

The attacker narrative must be written in first person and begin from an attacker viewpoint, similar to:
"If I were targeting yourbusiness.com, the first thing I'd notice is..."
Make it concrete and insightful, but never sensationalize the risk.

Return valid JSON matching this exact schema and nothing else:
{
  "executive_summary": "2-3 paragraph overview of the domain's security posture...",
  "attacker_narrative": "A first-person narrative from an attacker's perspective: 'If I were targeting yourbusiness.com, the first thing I'd notice is...'",
  "categories": [
    {
      "name": "Email Security",
      "grade": "D",
      "summary": "1-2 sentence category overview",
      "findings": [
        {
          "title": "No DMARC Policy Configured",
          "severity": "high",
          "explanation": "Plain English explanation with analogy...",
          "impact": "What could happen if this isn't fixed...",
          "remediation": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
          "difficulty": "easy"
        }
      ]
    }
  ],
  "action_items": [
    {
      "priority": 1,
      "title": "Set up DMARC email authentication",
      "category": "Email Security",
      "difficulty": "easy",
      "time_estimate": "15 minutes",
      "impact_if_ignored": "Attackers can send emails impersonating your business"
    }
  ]
}

Additional output constraints:
- Respond with a single JSON object only.
- Do not use markdown fences.
- Do not include commentary before or after the JSON.
- Keep category names aligned to the supplied scan categories.
- When a category has no findings, include an empty findings array and a reassuring summary.
""".strip()

SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

CATEGORY_DISPLAY_NAMES = {
    "dns": "DNS",
    "subdomains": "Subdomains",
    "ssl_tls": "SSL/TLS",
    "email_security": "Email Security",
    "headers": "HTTP Headers",
    "open_ports": "Open Ports",
    "tech_stack": "Tech Stack",
}


class AIReportFinding(BaseModel):
    """Validated finding payload expected back from the LLM."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(..., min_length=3)
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    explanation: str = Field(..., min_length=20)
    impact: str = Field(..., min_length=15)
    remediation: List[str] = Field(default_factory=list, min_length=1)
    difficulty: str = Field(..., pattern="^(easy|medium|hard)$")


class AIReportCategory(BaseModel):
    """Validated category payload expected back from the LLM."""

    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., min_length=2)
    grade: str = Field(..., pattern="^[ABCDF]$")
    summary: str = Field(..., min_length=12)
    findings: List[AIReportFinding] = Field(default_factory=list)


class AIActionItem(BaseModel):
    """Validated prioritized action item returned by the LLM."""

    model_config = ConfigDict(extra="ignore")

    priority: int = Field(..., ge=1)
    title: str = Field(..., min_length=3)
    category: str = Field(..., min_length=2)
    difficulty: str = Field(..., pattern="^(easy|medium|hard)$")
    time_estimate: str = Field(..., min_length=3)
    impact_if_ignored: str = Field(..., min_length=15)


class AIRawReport(BaseModel):
    """Validated top-level response shape returned by the LLM."""

    model_config = ConfigDict(extra="ignore")

    executive_summary: str = Field(..., min_length=60)
    attacker_narrative: str = Field(..., min_length=60)
    categories: List[AIReportCategory] = Field(default_factory=list)
    action_items: List[AIActionItem] = Field(default_factory=list)


def _truncate_findings(findings: List[Finding], limit: int) -> List[Finding]:
    """Keep the most important findings to control prompt size."""

    return sorted(findings, key=lambda finding: SEVERITY_RANK[finding.severity])[:limit]


def _dedupe_preserving_order(items: Iterable[str]) -> List[str]:
    """Return unique strings while preserving first-seen ordering."""

    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _difficulty_to_title_case(value: str) -> str:
    """Normalize difficulty values to the ActionItem model format."""

    mapping = {"easy": "Easy", "medium": "Medium", "hard": "Hard"}
    return mapping.get(value.lower(), "Medium")


def _priority_number_to_label(priority: int) -> str:
    """Map numeric action priority into the existing ActionItem severity-like label."""

    if priority <= 1:
        return "critical"
    if priority <= 3:
        return "high"
    if priority <= 6:
        return "medium"
    return "low"


def _strip_markdown_fences(response_text: str) -> str:
    """Remove surrounding markdown code fences if the model returned them."""

    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, count=1, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned, count=1)
    return cleaned.strip()


def _extract_json_object(response_text: str) -> str:
    """Extract the first full JSON object from a model response."""

    cleaned = _strip_markdown_fences(response_text)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object found in AI response.")
    return cleaned[start : end + 1]


def _generic_parse_fallback_report() -> FullReport:
    """Return a safe fallback when AI output cannot be parsed at all."""

    return FullReport(
        executive_summary=(
            "DomainVitals was able to collect the technical scan data, but the AI-generated"
            " narrative report could not be parsed into the required JSON format. The raw"
            " findings should still be treated as the source of truth for next steps."
        ),
        attacker_narrative=(
            "If I were reviewing this domain as an attacker, I would still start with the"
            " exposed internet-facing signals already found by the scan. A malformed AI"
            " response does not remove the need to review and remediate the highest-risk items."
        ),
        category_breakdowns=[
            ReportSection(
                title="Report Generation",
                summary=(
                    "The scan completed, but the language model response was malformed and"
                    " could not be converted into the final report structure."
                ),
                findings=[
                    "DomainVitals received an invalid AI response while building the human-readable report."
                ],
                remediation_steps=[
                    "Retry report generation.",
                    "Review the raw technical findings in the scan results.",
                    "Share the scan output with an IT consultant if manual interpretation is needed.",
                ],
            )
        ],
        prioritized_action_items=[
            ActionItem(
                title="Review raw scan findings manually",
                category="Report Generation",
                priority="medium",
                difficulty="Easy",
                rationale=(
                    "Until the report is regenerated successfully, the raw findings remain the"
                    " most reliable source for remediation planning."
                ),
                steps=[
                    "Open the scan results dashboard.",
                    "Review the highest-severity findings first.",
                    "Retry the AI report once connectivity and API responses are stable.",
                ],
            )
        ],
        model="fallback-parser",
    )


def _fallback_report(scan_result: ScanResult) -> FullReport:
    """Generate a deterministic report directly from scan results when AI is unavailable."""

    prioritized_findings = _truncate_findings(scan_result.findings, 5)
    sections: List[ReportSection] = []
    for module_name, module_result in scan_result.modules.items():
        title = CATEGORY_DISPLAY_NAMES.get(module_name, module_name.replace("_", " ").title())
        if module_result.findings:
            sections.append(
                ReportSection(
                    title=title,
                    summary=(
                        f"{title} surfaced {len(module_result.findings)} notable issue(s)."
                    ),
                    findings=[
                        f"{finding.title} ({finding.severity.value}): {finding.description}"
                        for finding in module_result.findings[:4]
                    ],
                    remediation_steps=_dedupe_preserving_order(
                        step
                        for finding in module_result.findings[:3]
                        for step in finding.remediation[:2]
                    ),
                )
            )
        else:
            sections.append(
                ReportSection(
                    title=title,
                    summary=(
                        f"{title} did not produce any notable issues during this passive scan."
                    ),
                    findings=["Positive note: no notable issues were identified in this category."],
                    remediation_steps=[
                        "Keep current controls in place and recheck this category on a regular basis."
                    ],
                )
            )

    action_items = [
        ActionItem(
            title=finding.title,
            category=CATEGORY_DISPLAY_NAMES.get(finding.category, finding.category.replace("_", " ").title()),
            priority=(
                "critical"
                if finding.severity == Severity.CRITICAL
                else "high"
                if finding.severity == Severity.HIGH
                else "medium"
                if finding.severity == Severity.MEDIUM
                else "low"
            ),
            difficulty="Medium",
            rationale=finding.impact,
            steps=finding.remediation,
        )
        for finding in prioritized_findings
    ]

    score = scan_result.risk_score.overall_score if scan_result.risk_score else 0
    return FullReport(
        executive_summary=(
            f"DomainVitals reviewed {scan_result.domain} and assigned an overall score of"
            f" {score}. The most important issues appear in the prioritized action list and"
            " category breakdowns below."
        ),
        attacker_narrative=(
            f"If I were targeting {scan_result.domain}, I would begin with the public clues"
            " exposed by DNS, HTTPS, email authentication, and any internet-facing services."
            " Those visible signals help attackers decide which paths are easiest to test first."
        ),
        category_breakdowns=sections,
        prioritized_action_items=action_items,
        model="fallback-deterministic",
    )


def build_user_prompt(scan_results: dict) -> str:
    """Format structured scan results into a readable user prompt for the model."""

    domain = scan_results.get("domain", "unknown-domain")
    scan_timestamp = (
        scan_results.get("completed_at")
        or scan_results.get("updated_at")
        or scan_results.get("created_at")
        or "unknown"
    )
    modules = scan_results.get("modules", {})
    risk_score = scan_results.get("risk_score")
    top_level_findings = scan_results.get("findings", [])

    category_sections: List[str] = []
    for module_name, module_result in modules.items():
        display_name = CATEGORY_DISPLAY_NAMES.get(module_name, module_name.replace("_", " ").title())
        findings = module_result.get("findings", [])
        if findings:
            rendered_findings = []
            for index, finding in enumerate(findings, start=1):
                rendered_findings.append(
                    (
                        f"  {index}. {finding.get('title', 'Untitled finding')}\n"
                        f"     severity: {finding.get('severity', 'unknown')}\n"
                        f"     description: {finding.get('description', 'No description provided.')}\n"
                        f"     impact: {finding.get('impact', 'No impact provided.')}\n"
                        f"     remediation: {finding.get('remediation', [])}\n"
                        f"     evidence: {finding.get('evidence', {})}"
                    )
                )
            findings_block = "\n".join(rendered_findings)
        else:
            findings_block = "  No findings reported in this category."

        category_sections.append(
            (
                f"- {display_name}\n"
                f"  module_key: {module_name}\n"
                f"  status: {module_result.get('status', 'unknown')}\n"
                f"  note: {module_result.get('note')}\n"
                f"  error: {module_result.get('error')}\n"
                f"  findings_count: {len(findings)}\n"
                f"{findings_block}\n"
                f"  raw_data: {json.dumps(module_result.get('data', {}), ensure_ascii=True, sort_keys=True)}"
            )
        )

    prompt = f"""
Create the DomainVitals security report for the domain below.

Return ONLY the JSON object described in the system prompt.
Do not wrap the response in markdown.
Do not add commentary before or after the JSON.

Domain: {domain}
Scan timestamp: {scan_timestamp}

Risk score summary:
{json.dumps(risk_score, indent=2, ensure_ascii=True, sort_keys=True) if risk_score is not None else "null"}

Readable category findings:
{chr(10).join(category_sections)}

All findings across the scan:
{json.dumps(top_level_findings, indent=2, ensure_ascii=True, sort_keys=True)}

Full raw scan results JSON:
{json.dumps(scan_results, indent=2, ensure_ascii=True, sort_keys=True)}
""".strip()

    return prompt


def _remediation_lookup(payload: AIRawReport) -> Dict[str, List[str]]:
    """Build a best-effort lookup from category/finding titles to remediation steps."""

    lookup: Dict[str, List[str]] = {}
    for category in payload.categories:
        for finding in category.findings:
            category_key = category.name.lower()
            title_key = finding.title.lower()
            lookup[f"{category_key}::{title_key}"] = finding.remediation
            lookup[category_key] = lookup.get(category_key, []) + finding.remediation
    return {key: _dedupe_preserving_order(value) for key, value in lookup.items()}


def _to_full_report(payload: AIRawReport) -> FullReport:
    """Convert the exact AI JSON schema into the backend's FullReport model."""

    remediation_map = _remediation_lookup(payload)
    sections: List[ReportSection] = []
    for category in payload.categories:
        if category.findings:
            finding_lines = [
                (
                    f"{finding.title} ({finding.severity}): {finding.explanation}"
                    f" Impact if ignored: {finding.impact}"
                )
                for finding in category.findings
            ]
            remediation_steps = _dedupe_preserving_order(
                step
                for finding in category.findings
                for step in finding.remediation
            )
        else:
            finding_lines = ["Positive note: no notable issues were identified in this category."]
            remediation_steps = [
                "Maintain current controls and keep monitoring this category over time."
            ]

        sections.append(
            ReportSection(
                title=category.name,
                summary=f"Grade {category.grade}. {category.summary}",
                findings=finding_lines,
                remediation_steps=remediation_steps,
            )
        )

    sorted_actions = sorted(payload.action_items, key=lambda item: item.priority)
    action_items: List[ActionItem] = []
    for item in sorted_actions:
        category_key = item.category.lower()
        action_items.append(
            ActionItem(
                title=item.title,
                category=item.category,
                priority=_priority_number_to_label(item.priority),
                difficulty=_difficulty_to_title_case(item.difficulty),
                rationale=(
                    f"{item.impact_if_ignored} Estimated effort: {item.time_estimate}."
                ),
                steps=remediation_map.get(category_key, []),
            )
        )

    return FullReport(
        executive_summary=payload.executive_summary,
        attacker_narrative=payload.attacker_narrative,
        category_breakdowns=sections,
        prioritized_action_items=action_items,
    )


def parse_ai_response(response_text: str) -> FullReport:
    """Strip fences, parse JSON, validate it, and return a safe FullReport object."""

    try:
        json_blob = _extract_json_object(response_text)
        raw_payload = json.loads(json_blob)
        validated_payload = AIRawReport.model_validate(raw_payload)
        report = _to_full_report(validated_payload)
        return FullReport.model_validate(report.model_dump())
    except (ValueError, json.JSONDecodeError, ValidationError):
        return _generic_parse_fallback_report()


def generate_ai_report(
    scan_result: ScanResult,
    *,
    api_key: Optional[str],
    model: str,
    max_findings: int,
    demo_mode: bool = False,
) -> FullReport:
    """Generate a full narrative report, falling back gracefully on errors."""

    if demo_mode and scan_result.domain.lower() == DEMO_DOMAIN and not api_key:
        report = load_demo_report_fixture()
        report.model = "demo-fixture"
        return report

    if not api_key:
        return _fallback_report(scan_result)

    try:
        from openai import OpenAI

        trimmed_result = scan_result.model_copy(
            update={"findings": _truncate_findings(scan_result.findings, max_findings)}
        )
        client = OpenAI(api_key=api_key)
        completion = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": build_user_prompt(trimmed_result.model_dump(mode="json")),
                },
            ],
        )
        content = completion.choices[0].message.content or "{}"
        report = parse_ai_response(content)
        if report.model == "fallback-parser":
            if demo_mode and scan_result.domain.lower() == DEMO_DOMAIN:
                fixture_report = load_demo_report_fixture()
                fixture_report.model = "demo-fixture"
                return fixture_report
            return _fallback_report(scan_result)
        report.model = model
        return report
    except Exception:
        if demo_mode and scan_result.domain.lower() == DEMO_DOMAIN:
            fixture_report = load_demo_report_fixture()
            fixture_report.model = "demo-fixture"
            return fixture_report
        return _fallback_report(scan_result)
