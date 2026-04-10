"""DNS reconnaissance routines for DomainVitals."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, List

import dns.exception
import dns.resolver

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


def _resolve_record(domain: str, record_type: str) -> List[str]:
    """Resolve a single DNS record type and return stringified answers."""

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    answers = resolver.resolve(domain, record_type)
    return [answer.to_text().strip() for answer in answers]


def _detect_wildcard_dns(domain: str) -> bool:
    """Check whether random subdomains resolve, indicating wildcard DNS."""

    random_name = f"{uuid.uuid4().hex[:12]}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    for record_type in ("A", "CNAME"):
        try:
            answers = resolver.resolve(random_name, record_type)
            if answers:
                return True
        except dns.exception.DNSException:
            continue
    return False


async def run_dns_recon(domain: str) -> ModuleResult:
    """Enumerate DNS records and flag common exposure patterns."""

    findings: List[Finding] = []
    records: Dict[str, Any] = {}

    async def query(record_type: str) -> None:
        try:
            values = await asyncio.to_thread(_resolve_record, domain, record_type)
            records[record_type] = values
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except dns.resolver.NXDOMAIN:
            raise
        except dns.exception.DNSException as exc:
            records[record_type] = {"error": str(exc)}

    try:
        await asyncio.gather(*(query(record_type) for record_type in RECORD_TYPES))
    except dns.resolver.NXDOMAIN:
        return ModuleResult(
            name="dns",
            status=ModuleStatus.ERROR,
            findings=[
                Finding(
                    title="Domain does not resolve in DNS",
                    category="dns",
                    severity=Severity.CRITICAL,
                    description=(
                        "The submitted domain could not be resolved through public DNS."
                    ),
                    impact=(
                        "If the public hostname does not resolve, customers and security"
                        " tools cannot reliably reach the site."
                    ),
                    remediation=[
                        "Confirm the domain is registered and delegated correctly.",
                        "Verify authoritative nameserver records at the registrar.",
                    ],
                    evidence={"domain": domain},
                )
            ],
            data={"records": records},
            error="Domain does not exist in public DNS.",
        )

    if not records.get("NS"):
        findings.append(
            Finding(
                title="No authoritative NS records returned",
                category="dns",
                severity=Severity.HIGH,
                description="The domain did not return any nameserver records.",
                impact=(
                    "Missing nameserver data can indicate a broken zone or an improperly"
                    " delegated domain."
                ),
                remediation=[
                    "Check your registrar delegation settings.",
                    "Confirm the authoritative DNS provider is active.",
                ],
                evidence={"record_type": "NS", "values": records.get("NS", [])},
            )
        )

    if not records.get("MX"):
        findings.append(
            Finding(
                title="No MX records published",
                category="dns",
                severity=Severity.LOW,
                description="No mail exchanger records were found for the domain.",
                impact=(
                    "If the business expects to receive email on this domain, inbound"
                    " mail delivery may fail or be handled unpredictably."
                ),
                remediation=[
                    "Add MX records if the domain is used for email.",
                    "If email is intentionally disabled, document that decision internally.",
                ],
                evidence={"record_type": "MX", "values": records.get("MX", [])},
            )
        )

    cname_records = records.get("CNAME", [])
    if isinstance(cname_records, list):
        for value in cname_records:
            target = value.rstrip(".")
            try:
                await asyncio.to_thread(_resolve_record, target, "A")
            except dns.exception.DNSException:
                findings.append(
                    Finding(
                        title="Potential dangling CNAME detected",
                        category="dns",
                        severity=Severity.HIGH,
                        description=(
                            "A CNAME target was published but the destination did not"
                            " resolve when checked."
                        ),
                        impact=(
                            "Dangling CNAME records can be abused for subdomain takeover"
                            " when third-party services are deprovisioned."
                        ),
                        remediation=[
                            "Remove the stale CNAME record if it is no longer needed.",
                            "Recreate the expected destination if the alias should remain active.",
                        ],
                        evidence={"record_type": "CNAME", "value": value},
                    )
                )

    wildcard_enabled = await asyncio.to_thread(_detect_wildcard_dns, domain)
    if wildcard_enabled:
        findings.append(
            Finding(
                title="Wildcard DNS appears enabled",
                category="dns",
                severity=Severity.MEDIUM,
                description=(
                    "Random subdomains resolved successfully, which suggests wildcard DNS"
                    " is configured for this zone."
                ),
                impact=(
                    "Wildcard DNS can hide stale or mistyped subdomains and make it harder"
                    " to track exposed hosts."
                ),
                remediation=[
                    "Review whether wildcard DNS is required for the application.",
                    "Limit wildcard behavior to the smallest necessary scope.",
                ],
                evidence={"wildcard_detected": True},
            )
        )

    return ModuleResult(
        name="dns",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data={"records": records, "wildcard_detected": wildcard_enabled},
        note="DNS recon finished successfully.",
    )
