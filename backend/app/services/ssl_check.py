"""TLS and certificate analysis for the scanned domain."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity


def _fetch_certificate_details(domain: str) -> Dict[str, Any]:
    """Open a TLS connection and extract certificate metadata."""

    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=6.0) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
            certificate = secure_sock.getpeercert()
            issuer = dict(item[0] for item in certificate.get("issuer", []))
            subject = dict(item[0] for item in certificate.get("subject", []))
            sans = [value for key, value in certificate.get("subjectAltName", []) if key == "DNS"]
            return {
                "issuer": issuer,
                "subject": subject,
                "sans": sans,
                "version": secure_sock.version(),
                "not_after": certificate.get("notAfter"),
                "not_before": certificate.get("notBefore"),
                "serial_number": certificate.get("serialNumber"),
                "certificate": certificate,
            }


async def run_ssl_check(domain: str) -> ModuleResult:
    """Inspect the HTTPS certificate and raise findings for weak TLS hygiene."""

    try:
        details = await asyncio.to_thread(_fetch_certificate_details, domain)
    except (OSError, ssl.SSLError) as exc:
        return ModuleResult(
            name="ssl_tls",
            status=ModuleStatus.ERROR,
            findings=[
                Finding(
                    title="HTTPS certificate could not be retrieved",
                    category="ssl_tls",
                    severity=Severity.HIGH,
                    description=(
                        "DomainVitals could not complete a TLS handshake with the submitted"
                        " domain on port 443."
                    ),
                    impact=(
                        "If HTTPS is misconfigured or unavailable, users may see certificate"
                        " warnings or downgrade to insecure connections."
                    ),
                    remediation=[
                        "Confirm the site serves HTTPS on port 443.",
                        "Install a valid certificate and verify the full certificate chain.",
                    ],
                    evidence={"domain": domain, "error": str(exc)},
                )
            ],
            data={},
            error=str(exc),
        )

    findings: List[Finding] = []
    not_after_raw = details.get("not_after")
    not_after = None
    days_until_expiry = None
    if not_after_raw:
        expiry_seconds = ssl.cert_time_to_seconds(not_after_raw)
        not_after = datetime.fromtimestamp(expiry_seconds, tz=timezone.utc)
        days_until_expiry = (not_after - datetime.now(timezone.utc)).days
        if days_until_expiry < 0:
            findings.append(
                Finding(
                    title="TLS certificate has expired",
                    category="ssl_tls",
                    severity=Severity.CRITICAL,
                    description="The certificate presented by the domain is already expired.",
                    impact=(
                        "Visitors will receive browser warnings, and attackers can exploit"
                        " trust breakdowns created by broken HTTPS."
                    ),
                    remediation=[
                        "Renew the certificate immediately.",
                        "Automate future certificate renewals and expiry monitoring.",
                    ],
                    evidence={"expiry_date": not_after.isoformat()},
                )
            )
        elif days_until_expiry <= 14:
            findings.append(
                Finding(
                    title="TLS certificate is close to expiry",
                    category="ssl_tls",
                    severity=Severity.MEDIUM,
                    description=(
                        "The active certificate will expire soon and should be renewed"
                        " proactively."
                    ),
                    impact=(
                        "Near-term expiry creates outage risk and can interrupt customer"
                        " access if renewal fails."
                    ),
                    remediation=[
                        "Renew the certificate before expiry.",
                        "Set up automated alerts for 30, 14, and 7 days before expiry.",
                    ],
                    evidence={"days_until_expiry": days_until_expiry},
                )
            )

    issuer = details.get("issuer", {})
    subject = details.get("subject", {})
    if issuer == subject:
        findings.append(
            Finding(
                title="Self-signed certificate detected",
                category="ssl_tls",
                severity=Severity.HIGH,
                description=(
                    "The certificate issuer matches the certificate subject, which indicates"
                    " a self-signed certificate."
                ),
                impact=(
                    "Self-signed certificates are not trusted by browsers and can train users"
                    " to ignore certificate warnings."
                ),
                remediation=[
                    "Replace the certificate with one issued by a trusted certificate authority.",
                ],
                evidence={"issuer": issuer, "subject": subject},
            )
        )

    protocol_version = details.get("version")
    if protocol_version in {"TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                title=f"Weak TLS protocol supported: {protocol_version}",
                category="ssl_tls",
                severity=Severity.HIGH,
                description=(
                    "The site negotiated an outdated TLS version that no longer meets"
                    " modern security standards."
                ),
                impact=(
                    "Legacy TLS versions are more susceptible to downgrade and cryptographic"
                    " attacks."
                ),
                remediation=[
                    "Disable TLS 1.0 and TLS 1.1 on the origin and load balancer.",
                    "Allow only TLS 1.2 and TLS 1.3 where possible.",
                ],
                evidence={"protocol_version": protocol_version},
            )
        )

    try:
        ssl.match_hostname(details["certificate"], domain)
    except ssl.CertificateError as exc:
        findings.append(
            Finding(
                title="Certificate hostname mismatch detected",
                category="ssl_tls",
                severity=Severity.CRITICAL,
                description=(
                    "The certificate subject alternative names did not match the requested"
                    " domain."
                ),
                impact=(
                    "A hostname mismatch breaks browser trust and can indicate misrouting or"
                    " misissued certificates."
                ),
                remediation=[
                    "Issue a certificate that includes the requested hostname.",
                    "Confirm DNS and load balancer routing points to the correct service.",
                ],
                evidence={"error": str(exc), "sans": details.get("sans", [])},
            )
        )

    return ModuleResult(
        name="ssl_tls",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data={
            "issuer": issuer,
            "subject": subject,
            "sans": details.get("sans", []),
            "protocol_version": protocol_version,
            "expires_at": not_after.isoformat() if not_after else None,
            "days_until_expiry": days_until_expiry,
            "serial_number": details.get("serial_number"),
        },
        note="TLS inspection completed.",
    )
