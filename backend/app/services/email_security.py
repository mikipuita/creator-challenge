"""Email authentication checks for SPF, DKIM, and DMARC."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity

COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail")
DMARC_POLICY_PATTERN = re.compile(r"\bp=([a-zA-Z]+)")


def _query_txt(name: str) -> List[str]:
    """Fetch TXT records for a hostname and join multi-string answers."""

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    answers = resolver.resolve(name, "TXT")
    values = []
    for answer in answers:
        if hasattr(answer, "strings"):
            values.append("".join(chunk.decode() for chunk in answer.strings))
        else:
            values.append(answer.to_text().replace('"', ""))
    return values


def _extract_spf(txt_records: List[str]) -> Optional[str]:
    """Return the first SPF TXT record if present."""

    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


async def run_email_security(domain: str) -> ModuleResult:
    """Assess SPF, DKIM, and DMARC posture for the target domain."""

    findings: List[Finding] = []
    data: Dict[str, Any] = {}

    try:
        root_txt = await asyncio.to_thread(_query_txt, domain)
    except dns.exception.DNSException:
        root_txt = []

    spf_record = _extract_spf(root_txt)
    if spf_record is None:
        findings.append(
            Finding(
                title="No SPF record found",
                category="email_security",
                severity=Severity.HIGH,
                description="No SPF policy was published in the domain's TXT records.",
                impact=(
                    "Without SPF, attackers can spoof mail from your domain more easily and"
                    " deliverability trust may suffer."
                ),
                remediation=[
                    "Publish a valid SPF record that lists your authorized mail senders.",
                    "End the policy with -all once the sender list is complete.",
                ],
                evidence={"txt_records": root_txt},
            )
        )
        data["spf"] = {
            "present": False,
            "record_value": None,
            "policy": None,
            "risk_level": "high",
            "explanation": "No SPF record was discovered.",
        }
    else:
        policy = None
        risk_level = "low"
        explanation = "SPF is published."
        if "-all" in spf_record:
            policy = "-all"
            explanation = "SPF ends in -all, which is the strongest enforcement mode."
        elif "~all" in spf_record:
            policy = "~all"
            risk_level = "medium"
            explanation = "SPF uses softfail (~all), which is less strict than a hard fail."
            findings.append(
                Finding(
                    title="SPF policy uses softfail",
                    category="email_security",
                    severity=Severity.MEDIUM,
                    description=(
                        "The SPF record ends in ~all rather than -all, which leaves more"
                        " room for unauthorized mail to slip through."
                    ),
                    impact=(
                        "Softfail policies offer weaker protection against spoofed mail than"
                        " fully enforced SPF."
                    ),
                    remediation=[
                        "Audit legitimate senders and move the SPF record to -all when ready.",
                    ],
                    evidence={"spf_record": spf_record},
                )
            )
        elif "?all" in spf_record:
            policy = "?all"
            risk_level = "high"
            explanation = "SPF uses ?all, which effectively disables enforcement."
            findings.append(
                Finding(
                    title="SPF policy is neutral",
                    category="email_security",
                    severity=Severity.HIGH,
                    description=(
                        "The SPF record ends in ?all, which signals neutrality rather than"
                        " blocking unauthorized senders."
                    ),
                    impact=(
                        "Neutral SPF provides little protection against impersonation."
                    ),
                    remediation=[
                        "Replace ?all with a more restrictive enforcement mode after validation.",
                    ],
                    evidence={"spf_record": spf_record},
                )
            )
        data["spf"] = {
            "present": True,
            "record_value": spf_record,
            "policy": policy,
            "risk_level": risk_level,
            "explanation": explanation,
        }

    dmarc_host = f"_dmarc.{domain}"
    try:
        dmarc_records = await asyncio.to_thread(_query_txt, dmarc_host)
    except dns.exception.DNSException:
        dmarc_records = []

    dmarc_record = next((record for record in dmarc_records if record.lower().startswith("v=dmarc1")), None)
    if dmarc_record is None:
        findings.append(
            Finding(
                title="No DMARC record found",
                category="email_security",
                severity=Severity.CRITICAL,
                description="No DMARC policy was published for the domain.",
                impact=(
                    "Without DMARC, anyone can send mail pretending to be your brand with"
                    " much less resistance from recipient systems."
                ),
                remediation=[
                    "Publish a DMARC record at _dmarc.<domain>.",
                    "Start with p=none for visibility, then move to quarantine or reject.",
                ],
                evidence={"host": dmarc_host},
            )
        )
        data["dmarc"] = {
            "present": False,
            "record_value": None,
            "policy": None,
            "risk_level": "critical",
            "explanation": "No DMARC record was discovered.",
        }
    else:
        match = DMARC_POLICY_PATTERN.search(dmarc_record)
        policy = match.group(1).lower() if match else None
        risk_level = "low"
        explanation = f"DMARC policy is set to {policy or 'unknown'}."
        if policy == "none":
            risk_level = "medium"
            findings.append(
                Finding(
                    title="DMARC is monitoring only",
                    category="email_security",
                    severity=Severity.MEDIUM,
                    description=(
                        "The domain publishes DMARC, but the policy is set to p=none rather"
                        " than enforcing quarantine or reject."
                    ),
                    impact=(
                        "Monitoring-only DMARC gives visibility into abuse but does not block"
                        " suspicious mail on its own."
                    ),
                    remediation=[
                        "Review DMARC aggregate reports and move toward p=quarantine or p=reject.",
                    ],
                    evidence={"dmarc_record": dmarc_record},
                )
            )
        data["dmarc"] = {
            "present": True,
            "record_value": dmarc_record,
            "policy": policy,
            "risk_level": risk_level,
            "explanation": explanation,
        }

    dkim_results = []
    for selector in COMMON_DKIM_SELECTORS:
        host = f"{selector}._domainkey.{domain}"
        try:
            records = await asyncio.to_thread(_query_txt, host)
            value = next((record for record in records if "v=DKIM1" in record.upper()), None)
            if value:
                dkim_results.append(
                    {
                        "selector": selector,
                        "present": True,
                        "record_value": value,
                        "policy": "dkim",
                        "risk_level": "low",
                        "explanation": f"DKIM selector {selector} was found.",
                    }
                )
        except dns.exception.DNSException:
            continue

    if not dkim_results:
        findings.append(
            Finding(
                title="Common DKIM selectors not found",
                category="email_security",
                severity=Severity.MEDIUM,
                description=(
                    "DomainVitals did not discover DKIM keys at several common selector"
                    " names."
                ),
                impact=(
                    "Missing DKIM reduces trust in outbound mail and weakens domain"
                    " impersonation defenses."
                ),
                remediation=[
                    "Confirm your email platform has DKIM enabled.",
                    "Publish the DKIM TXT record selectors provided by your mail vendor.",
                ],
                evidence={"checked_selectors": list(COMMON_DKIM_SELECTORS)},
            )
        )
        data["dkim"] = [
            {
                "selector": selector,
                "present": False,
                "record_value": None,
                "policy": None,
                "risk_level": "medium",
                "explanation": "No DKIM record found at this common selector.",
            }
            for selector in COMMON_DKIM_SELECTORS
        ]
    else:
        data["dkim"] = dkim_results

    return ModuleResult(
        name="email_security",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data=data,
        note="Email authentication review completed.",
    )
