"""Technology fingerprinting from headers, markup, and common paths."""

from __future__ import annotations

import re
from typing import Any, Dict, List

import httpx

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity

TECH_PATTERNS = {
    "wordpress": re.compile(r"wp-content|wp-includes|wordpress", re.IGNORECASE),
    "drupal": re.compile(r"drupal-settings-json|/sites/default/", re.IGNORECASE),
    "nextjs": re.compile(r"_next/static|__next_f", re.IGNORECASE),
}

GENERATOR_PATTERN = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
VERSION_DISCLOSURE_PATTERN = re.compile(r"/(\d+(?:\.\d+){1,3})")
LEGACY_SERVER_MARKERS = (
    "apache/2.2",
    "apache/2.4.4",
    "nginx/1.10",
    "nginx/1.12",
    "iis/7.5",
)


async def run_tech_fingerprint(domain: str, timeout_seconds: float) -> ModuleResult:
    """Identify visible technologies and flag risky disclosure patterns."""

    findings: List[Finding] = []
    detected: Dict[str, Any] = {"server": None, "x_powered_by": None, "generator": None, "technologies": []}

    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        headers={"User-Agent": "DomainVitals/1.0"},
        follow_redirects=True,
    ) as client:
        try:
            root_response = await client.get(f"https://{domain}")
            html = root_response.text
        except httpx.HTTPError as exc:
            return ModuleResult(
                name="tech_stack",
                status=ModuleStatus.ERROR,
                findings=[],
                data=detected,
                error=f"Failed to fingerprint technology stack: {exc}",
            )

        try:
            common_path_checks = await client.get(
                f"https://{domain}/wp-login.php",
                follow_redirects=False,
            )
        except httpx.HTTPError:
            common_path_checks = None

    server = root_response.headers.get("server")
    x_powered_by = root_response.headers.get("x-powered-by")
    generator_match = GENERATOR_PATTERN.search(html)
    generator = generator_match.group(1) if generator_match else None

    detected["server"] = server
    detected["x_powered_by"] = x_powered_by
    detected["generator"] = generator

    technologies = set()
    if server:
        technologies.add(server.split("/")[0])
    if x_powered_by:
        technologies.add(x_powered_by.split("/")[0])
    if generator:
        technologies.add(generator)
    for name, pattern in TECH_PATTERNS.items():
        if pattern.search(html):
            technologies.add(name)
    if common_path_checks and common_path_checks.status_code in {200, 302, 403}:
        technologies.add("wordpress")

    detected["technologies"] = sorted(technologies)

    for header_name, value in {"server": server, "x-powered-by": x_powered_by}.items():
        if value and VERSION_DISCLOSURE_PATTERN.search(value):
            findings.append(
                Finding(
                    title=f"Version disclosure in {header_name} header",
                    category="tech_stack",
                    severity=Severity.LOW,
                    description=(
                        f"The `{header_name}` header advertises technology version details to"
                        " visitors."
                    ),
                    impact=(
                        "Version disclosure gives attackers a faster starting point when"
                        " matching your stack to public vulnerabilities."
                    ),
                    remediation=[
                        f"Strip or generalize the `{header_name}` header in the web server or CDN.",
                    ],
                    evidence={"header": header_name, "value": value},
                )
            )
        if value and any(marker in value.lower() for marker in LEGACY_SERVER_MARKERS):
            findings.append(
                Finding(
                    title=f"Potentially outdated software disclosed in {header_name}",
                    category="tech_stack",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The `{header_name}` header appears to expose an older server version."
                    ),
                    impact=(
                        "Old web server versions are more likely to miss current security fixes"
                        " and hardening defaults."
                    ),
                    remediation=[
                        "Verify the running server version and upgrade if it is genuinely outdated.",
                        "Remove detailed version banners from public responses.",
                    ],
                    evidence={"header": header_name, "value": value},
                )
            )

    if "wordpress" in technologies:
        findings.append(
            Finding(
                title="WordPress indicators detected",
                category="tech_stack",
                severity=Severity.INFO,
                description=(
                    "Public response patterns suggest the site may be running WordPress."
                ),
                impact=(
                    "Popular CMS platforms are common attack targets, so plugin hygiene and"
                    " timely patching matter more."
                ),
                remediation=[
                    "Keep the core CMS, plugins, and themes fully patched.",
                    "Restrict public access to administrative endpoints where possible.",
                ],
                evidence={"detected_technology": "wordpress"},
            )
        )

    return ModuleResult(
        name="tech_stack",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data=detected,
        note="Technology fingerprinting completed.",
    )
