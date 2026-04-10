"""Passive certificate-based subdomain discovery via crt.sh."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity

SENSITIVE_LABELS = {"admin", "dev", "staging", "test", "beta", "internal", "old"}


def _parse_date(value: str | None) -> str | None:
    """Normalize crt.sh timestamps into ISO8601 when present."""

    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return value


async def run_subdomain_enum(domain: str, timeout_seconds: float) -> ModuleResult:
    """Look up certificate transparency data and summarize discovered subdomains."""

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    findings: List[Finding] = []

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url, headers={"User-Agent": "DomainVitals/1.0"})
            response.raise_for_status()
            payload: List[Dict[str, Any]] = response.json()
    except httpx.HTTPError as exc:
        return ModuleResult(
            name="subdomains",
            status=ModuleStatus.ERROR,
            findings=[],
            data={"subdomains": []},
            error=f"crt.sh lookup failed: {exc}",
        )
    except ValueError as exc:
        return ModuleResult(
            name="subdomains",
            status=ModuleStatus.ERROR,
            findings=[],
            data={"subdomains": []},
            error=f"crt.sh returned unreadable JSON: {exc}",
        )

    grouped: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"first_seen": None, "last_seen": None, "expired_cert_reference": False}
    )

    for entry in payload:
        names = str(entry.get("name_value", "")).splitlines()
        entry_ts = _parse_date(entry.get("entry_timestamp"))
        not_after = _parse_date(entry.get("not_after"))
        expired_reference = False
        if not_after:
            try:
                expired_reference = datetime.fromisoformat(not_after).timestamp() < datetime.now(
                    timezone.utc
                ).timestamp()
            except ValueError:
                expired_reference = False

        for raw_name in names:
            cleaned = raw_name.strip().lower().lstrip("*.").rstrip(".")
            if not cleaned or not cleaned.endswith(domain):
                continue
            record = grouped[cleaned]
            if entry_ts and (record["first_seen"] is None or entry_ts < record["first_seen"]):
                record["first_seen"] = entry_ts
            if entry_ts and (record["last_seen"] is None or entry_ts > record["last_seen"]):
                record["last_seen"] = entry_ts
            record["expired_cert_reference"] = (
                record["expired_cert_reference"] or expired_reference
            )

    subdomains = [
        {"name": name, **details}
        for name, details in sorted(grouped.items(), key=lambda item: item[0])
    ]

    for subdomain in subdomains:
        labels = set(subdomain["name"].split("."))
        risky_labels = sorted(labels.intersection(SENSITIVE_LABELS))
        if risky_labels:
            findings.append(
                Finding(
                    title=f"Potentially sensitive subdomain exposed: {subdomain['name']}",
                    category="subdomains",
                    severity=Severity.MEDIUM,
                    description=(
                        "Certificate transparency data references a subdomain whose name"
                        " suggests it may host non-public or pre-production systems."
                    ),
                    impact=(
                        "Labels like admin, dev, or staging often attract attackers because"
                        " they may expose weaker controls than the primary site."
                    ),
                    remediation=[
                        "Confirm the subdomain is still needed and externally reachable.",
                        "Apply production-grade access controls or retire the host.",
                    ],
                    evidence={"subdomain": subdomain["name"], "labels": risky_labels},
                )
            )

        if subdomain["expired_cert_reference"]:
            findings.append(
                Finding(
                    title=f"Expired certificate reference found for {subdomain['name']}",
                    category="subdomains",
                    severity=Severity.LOW,
                    description=(
                        "crt.sh includes at least one expired certificate entry for this"
                        " subdomain."
                    ),
                    impact=(
                        "Expired certificate references can indicate neglected assets or"
                        " forgotten services still associated with the business."
                    ),
                    remediation=[
                        "Verify whether the subdomain is still in use.",
                        "Remove abandoned DNS entries and renew certificates for active services.",
                    ],
                    evidence={"subdomain": subdomain["name"]},
                )
            )

    return ModuleResult(
        name="subdomains",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data={"subdomains": subdomains, "count": len(subdomains)},
        note=f"Discovered {len(subdomains)} unique subdomains from certificate logs.",
    )
