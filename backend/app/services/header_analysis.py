"""HTTP response header analysis for DomainVitals."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import httpx

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity

EXPECTED_HEADERS: Dict[str, Tuple[Severity, str]] = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HSTS helps browsers refuse insecure HTTP after the first secure visit.",
    ),
    "content-security-policy": (
        Severity.HIGH,
        "CSP reduces the blast radius of script injection and content tampering.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "This header helps stop MIME sniffing attacks in browsers.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "This header makes clickjacking attacks harder.",
    ),
    "x-xss-protection": (
        Severity.INFO,
        "Legacy browsers may use this flag as an additional XSS safety signal.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "A referrer policy reduces accidental disclosure of internal URLs and tokens.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Permissions-Policy limits access to browser features like camera or microphone.",
    ),
}


async def run_header_analysis(domain: str, timeout_seconds: float) -> ModuleResult:
    """Check security headers and HTTPS redirect behavior."""

    findings: List[Finding] = []
    data: Dict[str, Any] = {
        "https": {"status_code": None, "headers": {}, "error": None},
        "http": {"status_code": None, "headers": {}, "error": None},
        "redirects_to_https": False,
    }

    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        headers={"User-Agent": "DomainVitals/1.0"},
    ) as client:
        https_response = None
        http_response = None
        try:
            https_response = await client.get(f"https://{domain}")
            data["https"]["status_code"] = https_response.status_code
            data["https"]["headers"] = dict(https_response.headers)
        except httpx.HTTPError as exc:
            data["https"]["error"] = str(exc)

        try:
            http_response = await client.get(f"http://{domain}")
            data["http"]["status_code"] = http_response.status_code
            data["http"]["headers"] = dict(http_response.headers)
            location = http_response.headers.get("location", "")
            data["redirects_to_https"] = location.startswith("https://")
        except httpx.HTTPError as exc:
            data["http"]["error"] = str(exc)

    if https_response is None:
        findings.append(
            Finding(
                title="HTTPS endpoint was unreachable",
                category="headers",
                severity=Severity.HIGH,
                description="The scanner could not retrieve an HTTPS response from the domain.",
                impact=(
                    "If HTTPS is unavailable, customers may be forced onto insecure transport"
                    " or receive browser trust warnings."
                ),
                remediation=[
                    "Confirm the site is reachable over HTTPS.",
                    "Verify certificate, TLS termination, and origin health.",
                ],
                evidence={"error": data["https"]["error"]},
            )
        )
        return ModuleResult(
            name="headers",
            status=ModuleStatus.ERROR,
            findings=findings,
            data=data,
            error=data["https"]["error"],
        )

    normalized_headers = {key.lower(): value for key, value in https_response.headers.items()}
    for header_name, (severity, explanation) in EXPECTED_HEADERS.items():
        if header_name not in normalized_headers:
            findings.append(
                Finding(
                    title=f"Missing security header: {header_name}",
                    category="headers",
                    severity=severity,
                    description=(
                        f"The HTTPS response did not include `{header_name}`."
                    ),
                    impact=explanation,
                    remediation=[
                        f"Add the `{header_name}` header at the application or reverse proxy layer.",
                        "Test the header on all public-facing routes after deployment.",
                    ],
                    evidence={"header": header_name},
                )
            )

    if not data["redirects_to_https"]:
        findings.append(
            Finding(
                title="HTTP does not clearly redirect to HTTPS",
                category="headers",
                severity=Severity.MEDIUM,
                description=(
                    "The HTTP endpoint did not respond with a direct redirect to an HTTPS URL."
                ),
                impact=(
                    "Visitors or bots may access an insecure version of the site before"
                    " encryption is enforced."
                ),
                remediation=[
                    "Redirect all HTTP traffic to HTTPS at the edge.",
                    "Enable HSTS after confirming HTTPS is stable across the site.",
                ],
                evidence={"http_status": data["http"]["status_code"]},
            )
        )

    return ModuleResult(
        name="headers",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data=data,
        note="HTTP header analysis completed.",
    )
