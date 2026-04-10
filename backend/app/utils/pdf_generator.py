"""PDF report generation for DomainVitals security reports."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from typing import Iterable, List, Sequence

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, StyleSheet1, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    HRFlowable,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.models.report import ActionItem, FullReport, ReportSection
from app.models.scan import ScanResult

NAVY = HexColor("#0a0e1a")
DARK_BLUE = HexColor("#111827")
ACCENT_BLUE = HexColor("#3b82f6")
ACCENT_AMBER = HexColor("#f59e0b")
RED = HexColor("#ef4444")
GREEN = HexColor("#10b981")
YELLOW = HexColor("#eab308")
ORANGE = HexColor("#f97316")
WHITE = HexColor("#ffffff")
LIGHT_GRAY = HexColor("#e2e8f0")
MID_GRAY = HexColor("#94a3b8")
VERY_LIGHT_BLUE = HexColor("#eff6ff")

PAGE_WIDTH, PAGE_HEIGHT = LETTER
MARGIN = 0.75 * inch
CONTENT_WIDTH = PAGE_WIDTH - (2 * MARGIN)
CONTENT_HEIGHT = PAGE_HEIGHT - (2 * MARGIN)

GRADE_COLORS = {
    "A": GREEN,
    "B": ACCENT_BLUE,
    "C": YELLOW,
    "D": ORANGE,
    "F": RED,
}

SEVERITY_COLORS = {
    "critical": RED,
    "high": ORANGE,
    "medium": ACCENT_AMBER,
    "low": ACCENT_BLUE,
    "info": MID_GRAY,
}

DIFFICULTY_COLORS = {
    "easy": GREEN,
    "medium": YELLOW,
    "hard": RED,
}

PRIORITY_ORDER = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
}

GRADE_PATTERN = re.compile(r"\bGrade\s+([ABCDF])\b", re.IGNORECASE)
FINDING_PATTERN = re.compile(
    r"^(?P<title>.+?)\s+\((?P<severity>critical|high|medium|low|info)\):\s+"
    r"(?P<explanation>.+?)(?:\s+Impact if ignored:\s+(?P<impact>.+))?$",
    re.IGNORECASE | re.DOTALL,
)
EFFORT_PATTERN = re.compile(r"Estimated effort:\s*([^.]+)", re.IGNORECASE)


@dataclass
class PDFCategoryFinding:
    """Normalized finding content ready for rendering in the PDF."""

    title: str
    severity: str
    explanation: str
    impact: str
    remediation: List[str]
    difficulty: str


@dataclass
class PDFCategory:
    """Normalized category block ready for rendering in the PDF."""

    name: str
    grade: str
    summary: str
    findings: List[PDFCategoryFinding]


@dataclass
class PDFActionItem:
    """Normalized action plan row ready for table rendering."""

    priority: int
    title: str
    category: str
    difficulty: str
    time_estimate: str


def _safe_text(value: str | None, fallback: str = "Not available") -> str:
    """Return a normalized string value safe for display."""

    cleaned = (value or "").strip()
    return cleaned or fallback


def _paragraphs_from_text(text: str) -> List[str]:
    """Split paragraph text on blank lines while preserving readable chunks."""

    chunks = [chunk.strip() for chunk in re.split(r"\n\s*\n", text.strip()) if chunk.strip()]
    return chunks or [text.strip()]


def _severity_from_text(text: str) -> str:
    """Infer a severity label from text when it is not explicitly present."""

    lowered = text.lower()
    for severity in ("critical", "high", "medium", "low", "info"):
        if f" {severity} " in f" {lowered} " or f"({severity})" in lowered:
            return severity
    return "info"


def _extract_grade(summary: str, findings: Sequence[str]) -> str:
    """Infer a category grade from the summary or fallback heuristics."""

    match = GRADE_PATTERN.search(summary)
    if match:
        return match.group(1).upper()

    joined = " ".join(findings).lower()
    if "critical" in joined:
        return "F"
    if "high" in joined:
        return "D"
    if "medium" in joined:
        return "C"
    if "low" in joined:
        return "B"
    return "A"


def _difficulty_from_category_actions(category: str, actions: Sequence[ActionItem]) -> str:
    """Infer a difficulty level for category findings from matching action items."""

    normalized = category.lower()
    for action in actions:
        if action.category.lower() == normalized:
            return action.difficulty.lower()
    return "medium"


def _time_estimate_for_action(action: ActionItem) -> str:
    """Infer a time estimate from the stored rationale or difficulty."""

    match = EFFORT_PATTERN.search(action.rationale)
    if match:
        return match.group(1).strip()

    defaults = {
        "Easy": "15-30 minutes",
        "Medium": "1-2 hours",
        "Hard": "Half day+",
    }
    return defaults.get(action.difficulty, "Varies")


def _normalize_remediation(
    remediation: Iterable[str],
    fallback: Sequence[str] | None = None,
) -> List[str]:
    """Return deduplicated remediation steps with a safe fallback."""

    seen: set[str] = set()
    normalized: List[str] = []
    for step in remediation:
        candidate = step.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)

    if normalized:
        return normalized

    return list(
        fallback
        or [
            "Review this item with your IT consultant or managed service provider.",
            "Confirm the issue is still present in production.",
            "Document the fix and re-run the scan to verify the improvement.",
        ]
    )


def _parse_finding_line(
    line: str,
    category: str,
    category_steps: Sequence[str],
    actions: Sequence[ActionItem],
) -> PDFCategoryFinding:
    """Parse a report finding string into structured PDF finding data."""

    match = FINDING_PATTERN.match(line.strip())
    if match:
        title = match.group("title").strip()
        severity = match.group("severity").lower()
        explanation = match.group("explanation").strip()
        impact = _safe_text(
            match.group("impact"),
            fallback="This issue may make the business easier to impersonate, disrupt, or probe.",
        )
    else:
        title = line.split(":", 1)[0].strip()[:120] or "Security Finding"
        severity = _severity_from_text(line)
        explanation = line.strip()
        impact = (
            "If ignored, this issue may increase the chance of impersonation, service exposure,"
            " or easier reconnaissance by attackers."
        )

    difficulty = _difficulty_from_category_actions(category, actions)
    remediation = _normalize_remediation(category_steps)

    category_lower = category.lower()
    for action in actions:
        if action.category.lower() != category_lower:
            continue
        if title.lower() in action.title.lower() or action.title.lower() in title.lower():
            difficulty = action.difficulty.lower()
            remediation = _normalize_remediation(action.steps, fallback=remediation)
            break

    if "positive note:" in title.lower():
        severity = "info"
        difficulty = "easy"
        impact = "This category appears healthy based on the available passive scan evidence."
        remediation = [
            "Keep the current controls in place.",
            "Monitor this area during routine security reviews.",
        ]

    return PDFCategoryFinding(
        title=title,
        severity=severity,
        explanation=explanation,
        impact=impact,
        remediation=remediation,
        difficulty=difficulty,
    )


def _normalize_categories(report: FullReport) -> List[PDFCategory]:
    """Convert the report model into category structures for PDF rendering."""

    categories: List[PDFCategory] = []
    for section in report.category_breakdowns:
        grade = _extract_grade(section.summary, section.findings)
        findings = [
            _parse_finding_line(
                line,
                section.title,
                section.remediation_steps,
                report.prioritized_action_items,
            )
            for line in section.findings
        ]

        if not findings:
            findings = [
                PDFCategoryFinding(
                    title="No notable issues identified",
                    severity="info",
                    explanation=(
                        "DomainVitals did not find any notable problems in this category during"
                        " the passive review."
                    ),
                    impact="This is a positive signal, although regular re-checks still matter.",
                    remediation=[
                        "Keep the current protections in place.",
                        "Repeat the scan after meaningful infrastructure changes.",
                    ],
                    difficulty="easy",
                )
            ]

        categories.append(
            PDFCategory(
                name=section.title,
                grade=grade,
                summary=section.summary,
                findings=findings,
            )
        )

    if categories:
        return categories

    return [
        PDFCategory(
            name="General Findings",
            grade="B",
            summary=(
                "The report did not include category breakdowns, so DomainVitals generated a"
                " simplified summary page."
            ),
            findings=[
                PDFCategoryFinding(
                    title="Review scan results manually",
                    severity="info",
                    explanation=(
                        "The high-level report content was incomplete, so the raw findings should"
                        " be reviewed directly."
                    ),
                    impact="Important remediation details may be easier to miss without a full narrative report.",
                    remediation=[
                        "Open the raw scan output.",
                        "Review the highest-severity items first.",
                        "Regenerate the report if needed.",
                    ],
                    difficulty="easy",
                )
            ],
        )
    ]


def _normalize_action_items(report: FullReport) -> List[PDFActionItem]:
    """Convert the report action items into table rows with numeric priorities."""

    if report.prioritized_action_items:
        normalized = [
            PDFActionItem(
                priority=index,
                title=item.title,
                category=item.category,
                difficulty=item.difficulty,
                time_estimate=_time_estimate_for_action(item),
            )
            for index, item in enumerate(
                sorted(
                    report.prioritized_action_items,
                    key=lambda action: (
                        PRIORITY_ORDER.get(action.priority, 99),
                        action.title.lower(),
                    ),
                ),
                start=1,
            )
        ]
        return normalized

    categories = _normalize_categories(report)
    return [
        PDFActionItem(
            priority=index,
            title=f"Review {category.name}",
            category=category.name,
            difficulty="Medium",
            time_estimate="1-2 hours",
        )
        for index, category in enumerate(categories, start=1)
    ]


def _build_styles() -> StyleSheet1:
    """Construct the paragraph styles used across all content pages."""

    styles = getSampleStyleSheet()
    styles["BodyText"].fontName = "Helvetica"
    styles["BodyText"].fontSize = 10.5
    styles["BodyText"].leading = 15
    styles["BodyText"].textColor = DARK_BLUE
    styles["BodyText"].alignment = TA_JUSTIFY

    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=MID_GRAY,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=DARK_BLUE,
            alignment=TA_LEFT,
            spaceAfter=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CategoryTitle",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=DARK_BLUE,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=12.5,
            leading=16,
            textColor=DARK_BLUE,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ImpactText",
            parent=styles["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=10,
            leading=14,
            textColor=DARK_BLUE,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BlockQuote",
            parent=styles["BodyText"],
            fontSize=10.5,
            leading=16,
            leftIndent=14,
            rightIndent=6,
            textColor=DARK_BLUE,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FooterBrand",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=MID_GRAY,
            alignment=TA_CENTER,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableCell",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=12,
            textColor=DARK_BLUE,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableCellCenter",
            parent=styles["TableCell"],
            alignment=TA_CENTER,
        )
    )
    return styles


def _draw_tracked_text(
    canvas: Canvas,
    text: str,
    center_x: float,
    y: float,
    font_name: str,
    font_size: float,
    tracking: float,
    color: Color,
) -> None:
    """Draw text with visible tracking centered on the page."""

    glyph_widths = [stringWidth(char, font_name, font_size) for char in text]
    total_width = sum(glyph_widths) + max(len(text) - 1, 0) * tracking
    current_x = center_x - (total_width / 2)

    canvas.saveState()
    canvas.setFillColor(color)
    canvas.setFont(font_name, font_size)
    for index, char in enumerate(text):
        canvas.drawString(current_x, y, char)
        current_x += glyph_widths[index] + tracking
    canvas.restoreState()


def _draw_cover_page(
    canvas: Canvas,
    domain: str,
    scan_date: str,
    grade: str,
    score: int,
) -> None:
    """Render the custom cover page directly with canvas primitives."""

    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=1, stroke=0)

    _draw_tracked_text(
        canvas,
        "DOMAINVITALS",
        PAGE_WIDTH / 2,
        PAGE_HEIGHT - 110,
        "Helvetica-Bold",
        24,
        2.8,
        WHITE,
    )

    canvas.setFillColor(LIGHT_GRAY)
    canvas.setFont("Helvetica", 12)
    canvas.drawCentredString(PAGE_WIDTH / 2, PAGE_HEIGHT - 138, "SECURITY ASSESSMENT REPORT")

    canvas.setStrokeColor(ACCENT_BLUE)
    canvas.setLineWidth(2)
    canvas.line(MARGIN + 48, PAGE_HEIGHT - 160, PAGE_WIDTH - MARGIN - 48, PAGE_HEIGHT - 160)

    circle_radius = 62
    circle_center_y = PAGE_HEIGHT - 295
    grade_color = GRADE_COLORS.get(grade.upper(), ACCENT_BLUE)
    canvas.setFillColor(grade_color)
    canvas.circle(PAGE_WIDTH / 2, circle_center_y, circle_radius, fill=1, stroke=0)

    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 56)
    canvas.drawCentredString(PAGE_WIDTH / 2, circle_center_y - 20, grade.upper())

    canvas.setFillColor(LIGHT_GRAY)
    canvas.setFont("Helvetica-Bold", 15)
    canvas.drawCentredString(PAGE_WIDTH / 2, circle_center_y - 92, f"Overall Score: {score}/100")

    domain_style = ParagraphStyle(
        "CoverDomain",
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=28,
        textColor=WHITE,
        alignment=TA_CENTER,
    )
    domain_paragraph = Paragraph(domain, domain_style)
    domain_width = CONTENT_WIDTH - 32
    width, height = domain_paragraph.wrap(domain_width, 120)
    domain_paragraph.drawOn(canvas, MARGIN + 16, circle_center_y - 162 - height)

    canvas.setFillColor(LIGHT_GRAY)
    canvas.setFont("Helvetica", 12)
    canvas.drawCentredString(PAGE_WIDTH / 2, 180, f"Scan Date: {scan_date}")

    footer_style = ParagraphStyle(
        "CoverFooter",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=MID_GRAY,
        alignment=TA_CENTER,
    )
    footer = Paragraph(
        "This report was generated by DomainVitals &mdash; AI-powered security analysis",
        footer_style,
    )
    footer.wrapOn(canvas, CONTENT_WIDTH, 40)
    footer.drawOn(canvas, MARGIN, 66)

    canvas.restoreState()


def _draw_page_footer(canvas: Canvas, doc: BaseDocTemplate) -> None:
    """Draw page number and brand footer for content pages."""

    canvas.saveState()
    canvas.setStrokeColor(LIGHT_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, MARGIN - 8, PAGE_WIDTH - MARGIN, MARGIN - 8)
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(MID_GRAY)
    canvas.drawString(MARGIN, MARGIN - 22, "DomainVitals Security Assessment")
    canvas.drawRightString(PAGE_WIDTH - MARGIN, MARGIN - 22, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _on_cover_page(
    canvas: Canvas,
    doc: BaseDocTemplate,
    *,
    domain: str,
    scan_date: str,
    grade: str,
    score: int,
) -> None:
    """Canvas callback for the cover page template."""

    _draw_cover_page(canvas, domain=domain, scan_date=scan_date, grade=grade, score=score)


def _section_header(title: str, border_color: Color, styles: StyleSheet1) -> Table:
    """Create a reusable left-bar section header."""

    header = Table(
        [[Paragraph(title, styles["SectionLabel"])]],
        colWidths=[CONTENT_WIDTH],
    )
    header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                ("LINEBEFORE", (0, 0), (0, 0), 5, border_color),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return header


def _badge(text: str, background: Color, text_color: Color = WHITE) -> Table:
    """Create a small pill or badge with centered text."""

    badge = Table([[Paragraph(text, ParagraphStyle(
        "BadgeText",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=text_color,
        alignment=TA_CENTER,
    ))]])
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROUNDEDCORNERS", [8, 8, 8, 8]),
            ]
        )
    )
    return badge


def _grade_badge(grade: str) -> Table:
    """Create a circular-looking colored grade badge for a category header."""

    color = GRADE_COLORS.get(grade.upper(), ACCENT_BLUE)
    badge = Table(
        [[Paragraph(
            grade.upper(),
            ParagraphStyle(
                "GradeBadgeText",
                fontName="Helvetica-Bold",
                fontSize=14,
                leading=16,
                textColor=WHITE,
                alignment=TA_CENTER,
            ),
        )]],
        colWidths=[0.42 * inch],
        rowHeights=[0.42 * inch],
    )
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("ROUNDEDCORNERS", [18, 18, 18, 18]),
            ]
        )
    )
    return badge


def _category_header(category: PDFCategory, styles: StyleSheet1) -> Table:
    """Build a category header row with the grade badge."""

    header = Table(
        [[_grade_badge(category.grade), Paragraph(category.name, styles["CategoryTitle"])]],
        colWidths=[0.6 * inch, CONTENT_WIDTH - 0.6 * inch],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return header


def _finding_flowables(finding: PDFCategoryFinding, styles: StyleSheet1) -> List:
    """Create the flowables for an individual finding block."""

    severity_color = SEVERITY_COLORS.get(finding.severity.lower(), MID_GRAY)
    difficulty_color = DIFFICULTY_COLORS.get(finding.difficulty.lower(), YELLOW)

    remediation_list = ListFlowable(
        [
            ListItem(
                Paragraph(step, styles["BodyText"]),
                value=index,
            )
            for index, step in enumerate(finding.remediation, start=1)
        ],
        bulletType="1",
        leftIndent=16,
        bulletFontName="Helvetica-Bold",
        bulletFontSize=9,
    )

    badge_row = Table(
        [[
            _badge(finding.severity.upper(), severity_color),
            Spacer(0.12 * inch, 0.1),
            Paragraph(finding.title, styles["FindingTitle"]),
        ]],
        colWidths=[0.95 * inch, 0.12 * inch, CONTENT_WIDTH - 1.07 * inch],
    )
    badge_row.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    difficulty_table = Table(
        [[Paragraph(
            finding.difficulty.upper(),
            ParagraphStyle(
                "DifficultyText",
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=WHITE if difficulty_color != YELLOW else DARK_BLUE,
                alignment=TA_CENTER,
            ),
        )]]
    )
    difficulty_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), difficulty_color),
                ("ROUNDEDCORNERS", [9, 9, 9, 9]),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    return [
        badge_row,
        Spacer(1, 0.12 * inch),
        Paragraph(finding.explanation, styles["BodyText"]),
        Spacer(1, 0.08 * inch),
        Paragraph(f"<i>{finding.impact}</i>", styles["ImpactText"]),
        Spacer(1, 0.1 * inch),
        Paragraph("<b>How to Fix:</b>", styles["BodyText"]),
        Spacer(1, 0.04 * inch),
        remediation_list,
        Spacer(1, 0.1 * inch),
        difficulty_table,
        Spacer(1, 0.14 * inch),
        HRFlowable(width="100%", color=LIGHT_GRAY, thickness=0.6, spaceAfter=0, spaceBefore=0),
        Spacer(1, 0.16 * inch),
    ]


def _executive_summary_page(report: FullReport, styles: StyleSheet1) -> List:
    """Build the executive summary and attacker narrative flowables."""

    story: List = []
    story.append(_section_header("EXECUTIVE SUMMARY", ACCENT_BLUE, styles))
    story.append(Spacer(1, 0.18 * inch))
    for paragraph in _paragraphs_from_text(report.executive_summary):
        story.append(Paragraph(paragraph, styles["BodyText"]))
        story.append(Spacer(1, 0.12 * inch))

    story.append(Spacer(1, 0.12 * inch))
    story.append(_section_header("ATTACKER'S PERSPECTIVE", ACCENT_AMBER, styles))
    story.append(Spacer(1, 0.18 * inch))

    narrative_block = Table(
        [[Paragraph(paragraph, styles["BlockQuote"])] for paragraph in _paragraphs_from_text(report.attacker_narrative)],
        colWidths=[CONTENT_WIDTH],
    )
    narrative_block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), VERY_LIGHT_BLUE),
                ("LINEBEFORE", (0, 0), (0, -1), 4, ACCENT_AMBER),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(narrative_block)
    return story


def _category_pages(categories: Sequence[PDFCategory], styles: StyleSheet1) -> List:
    """Build the category breakdown pages."""

    story: List = []
    for index, category in enumerate(categories):
        if index == 0:
            story.append(PageBreak())
        else:
            story.append(CondPageBreak(3.2 * inch))

        story.append(_category_header(category, styles))
        story.append(Spacer(1, 0.16 * inch))
        story.append(Paragraph(category.summary, styles["BodyText"]))
        story.append(Spacer(1, 0.2 * inch))

        if category.findings:
            for finding in category.findings:
                story.extend(_finding_flowables(finding, styles))
        else:
            story.append(
                Paragraph(
                    "No findings were provided for this category. DomainVitals treated this as a positive note.",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 0.18 * inch))

        if index < len(categories) - 1:
            story.append(PageBreak())

    return story


def _action_plan_page(
    action_items: Sequence[PDFActionItem],
    disclaimer: str,
    styles: StyleSheet1,
) -> List:
    """Build the final prioritized action plan page."""

    story: List = [PageBreak(), _section_header("PRIORITIZED ACTION PLAN", ACCENT_BLUE, styles), Spacer(1, 0.18 * inch)]

    rows = [
        [
            Paragraph("<b>Priority #</b>", styles["TableCellCenter"]),
            Paragraph("<b>Action</b>", styles["TableCell"]),
            Paragraph("<b>Category</b>", styles["TableCell"]),
            Paragraph("<b>Difficulty</b>", styles["TableCellCenter"]),
            Paragraph("<b>Time Estimate</b>", styles["TableCellCenter"]),
        ]
    ]

    for item in action_items:
        rows.append(
            [
                Paragraph(str(item.priority), styles["TableCellCenter"]),
                Paragraph(item.title, styles["TableCell"]),
                Paragraph(item.category, styles["TableCell"]),
                Paragraph(item.difficulty, styles["TableCellCenter"]),
                Paragraph(item.time_estimate, styles["TableCellCenter"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[0.65 * inch, 2.35 * inch, 1.45 * inch, 1.0 * inch, 1.55 * inch],
        repeatRows=1,
    )
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    for row_index in range(1, len(rows)):
        background = WHITE if row_index % 2 else VERY_LIGHT_BLUE
        table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), background))
    table.setStyle(TableStyle(table_style))

    story.append(table)
    story.append(Spacer(1, 0.24 * inch))
    story.append(
        Paragraph(
            "Questions? Share this report with your IT consultant or managed service provider.",
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(disclaimer, styles["BodySmall"]))
    story.append(Spacer(1, 0.18 * inch))
    story.append(Paragraph("DomainVitals &middot; AI-powered security analysis", styles["FooterBrand"]))
    return story


def generate_pdf(
    report: FullReport,
    domain: str,
    scan_date: str,
    grade: str,
    score: int,
) -> bytes:
    """Generate the DomainVitals PDF report and return it as bytes."""

    styles = _build_styles()
    categories = _normalize_categories(report)
    action_items = _normalize_action_items(report)
    buffer = BytesIO()

    document = BaseDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title=f"DomainVitals Security Report - {domain}",
        author="DomainVitals",
        subject="Security Assessment Report",
    )

    frame = Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        id="content",
    )

    cover_template = PageTemplate(
        id="Cover",
        frames=[frame],
        onPage=lambda canvas, doc: _on_cover_page(
            canvas,
            doc,
            domain=domain,
            scan_date=scan_date,
            grade=grade,
            score=score,
        ),
    )
    content_template = PageTemplate(
        id="Content",
        frames=[frame],
        onPage=_draw_page_footer,
    )
    document.addPageTemplates([cover_template, content_template])

    story: List = [
        Spacer(1, CONTENT_HEIGHT - 8),
        NextPageTemplate("Content"),
        PageBreak(),
    ]
    story.extend(_executive_summary_page(report, styles))
    story.extend(_category_pages(categories, styles))
    story.extend(_action_plan_page(action_items, report.disclaimer, styles))

    document.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def generate_pdf_report(scan_result: ScanResult) -> bytes:
    """Compatibility wrapper used by the FastAPI router."""

    if not scan_result.report or not scan_result.risk_score:
        raise ValueError("A completed report and risk score are required before exporting PDF.")

    scan_date = (
        scan_result.completed_at
        or scan_result.updated_at
        or scan_result.created_at
    ).strftime("%B %d, %Y")

    return generate_pdf(
        report=scan_result.report,
        domain=scan_result.domain,
        scan_date=scan_date,
        grade=scan_result.risk_score.overall_grade,
        score=int(round(scan_result.risk_score.overall_score)),
    )


def generate_fallback_pdf_report(scan_result: ScanResult, error_message: str | None = None) -> bytes:
    """Generate a minimal PDF when the full branded layout fails."""

    if not scan_result.report or not scan_result.risk_score:
        raise ValueError("A completed report and risk score are required before exporting PDF.")

    buffer = BytesIO()
    canvas = Canvas(buffer, pagesize=LETTER)
    width, height = LETTER
    x = MARGIN
    y = height - MARGIN

    def new_page() -> None:
        nonlocal y
        canvas.showPage()
        y = height - MARGIN

    def write_line(text: str, *, font: str = "Helvetica", size: float = 10, color=LIGHT_GRAY, gap: float = 14) -> None:
        nonlocal y
        if y < MARGIN + 48:
            new_page()
        canvas.setFont(font, size)
        canvas.setFillColor(color)
        canvas.drawString(x, y, text[:120])
        y -= gap

    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)

    write_line("DOMAINVITALS SECURITY ASSESSMENT", font="Helvetica-Bold", size=20, color=WHITE, gap=22)
    write_line(f"Domain: {scan_result.domain}", font="Helvetica-Bold", size=13, color=WHITE, gap=18)
    write_line(
        f"Score: {int(round(scan_result.risk_score.overall_score))}/100  Grade: {scan_result.risk_score.overall_grade}",
        font="Helvetica-Bold",
        size=12,
        color=WHITE,
        gap=18,
    )
    write_line(
        f"Scan date: {(scan_result.completed_at or scan_result.updated_at or scan_result.created_at).strftime('%B %d, %Y')}",
        size=11,
        gap=20,
    )

    if error_message:
        write_line("Note: the full branded PDF layout failed, so DomainVitals generated this simplified export.", color=ACCENT_AMBER, gap=16)
        write_line(f"PDF layout error: {error_message}", color=ACCENT_AMBER, gap=20)

    write_line("Executive Summary", font="Helvetica-Bold", size=14, color=WHITE, gap=18)
    for paragraph in _paragraphs_from_text(scan_result.report.executive_summary):
        for line in re.findall(r".{1,105}(?:\s|$)", paragraph):
            if line.strip():
                write_line(line.strip(), size=10.5)
        y -= 4

    write_line("Attacker Perspective", font="Helvetica-Bold", size=14, color=WHITE, gap=18)
    for paragraph in _paragraphs_from_text(scan_result.report.attacker_narrative):
        for line in re.findall(r".{1,105}(?:\s|$)", paragraph):
            if line.strip():
                write_line(line.strip(), size=10.5)
        y -= 4

    write_line("Top Action Items", font="Helvetica-Bold", size=14, color=WHITE, gap=18)
    for index, item in enumerate(scan_result.report.prioritized_action_items[:8], start=1):
        write_line(f"{index}. {item.title} [{item.difficulty}]", font="Helvetica-Bold", size=11, color=WHITE, gap=16)
        write_line(f"Category: {item.category}", size=10)
        write_line(item.rationale, size=10)
        for step in item.steps[:3]:
            write_line(f"- {step}", size=10)
        y -= 4

    canvas.save()
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
