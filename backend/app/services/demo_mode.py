"""Pre-built demo scan data and helpers for live presentations."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Dict

from app.models.report import FullReport
from app.models.scan import CategoryScore, Finding, ModuleResult, ModuleStatus, RiskScore, Severity

DEMO_DOMAIN = "demo.threatlens.io"
FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures"
DEMO_REPORT_FIXTURE = FIXTURE_DIR / "demo_report.json"
DEMO_MODULE_DELAYS = {
    "dns": 0.6,
    "subdomains": 0.9,
    "ssl_tls": 1.2,
    "email_security": 1.4,
    "headers": 1.6,
    "open_ports": 1.8,
    "tech_stack": 2.0,
}


def is_demo_scan(domain: str, demo_mode_enabled: bool) -> bool:
    """Return True when the special demo scan path should be used."""

    return demo_mode_enabled and domain.lower() == DEMO_DOMAIN


def load_demo_report_fixture() -> FullReport:
    """Load and validate the pre-written demo report fixture."""

    return FullReport.model_validate_json(DEMO_REPORT_FIXTURE.read_text(encoding="utf-8"))


def build_demo_risk_score() -> RiskScore:
    """Return the fixed scorecard used for demo presentations."""

    return RiskScore(
        overall_grade="C",
        overall_score=72.0,
        category_scores=[
            CategoryScore(name="email_security", score=58.0, weight=25.0, findings_count=3),
            CategoryScore(name="ssl_tls", score=80.0, weight=20.0, findings_count=1),
            CategoryScore(name="headers", score=68.0, weight=20.0, findings_count=3),
            CategoryScore(name="open_ports", score=74.0, weight=15.0, findings_count=1),
            CategoryScore(name="dns", score=90.0, weight=10.0, findings_count=3),
            CategoryScore(name="tech_stack", score=78.0, weight=10.0, findings_count=3),
        ],
        critical_findings_count=2,
        high_findings_count=3,
    )


def _finding(
    *,
    title: str,
    category: str,
    severity: Severity,
    description: str,
    impact: str,
    remediation: list[str],
    evidence: dict,
) -> Finding:
    """Small helper for creating repeatable demo findings."""

    return Finding(
        title=title,
        category=category,
        severity=severity,
        description=description,
        impact=impact,
        remediation=remediation,
        evidence=evidence,
    )


def build_demo_modules() -> Dict[str, ModuleResult]:
    """Construct the full set of pre-built demo module results."""

    return {
        "dns": ModuleResult(
            name="dns",
            status=ModuleStatus.COMPLETE,
            note="Passive DNS recon completed against a fictional retail business.",
            data={
                "records": {
                    "A": ["203.0.113.42"],
                    "AAAA": [],
                    "MX": ["10 aspmx.l.google.com."],
                    "TXT": ["v=spf1 include:_spf.google.com ~all"],
                    "NS": ["ns-cloud-a1.googledomains.com.", "ns-cloud-a2.googledomains.com."],
                    "CNAME": [],
                    "SOA": ["ns-cloud-a1.googledomains.com. dns-admin.google.com. 12 21600 3600 259200 300"],
                },
                "wildcard_detected": True,
            },
            findings=[
                _finding(
                    title="Wildcard DNS is enabled",
                    category="dns",
                    severity=Severity.MEDIUM,
                    description=(
                        "Random subdomains resolve successfully, which suggests wildcard DNS is"
                        " turned on for the domain."
                    ),
                    impact=(
                        "Wildcard DNS can hide forgotten systems and make it easier for attackers"
                        " to find weak or abandoned hosts."
                    ),
                    remediation=[
                        "Review whether wildcard DNS is still required.",
                        "Limit it to the smallest set of hosts possible.",
                        "Retest public subdomains after tightening the configuration.",
                    ],
                    evidence={"wildcard_detected": True},
                ),
                _finding(
                    title="Cloud-managed DNS is in use",
                    category="dns",
                    severity=Severity.INFO,
                    description=(
                        "The domain is using a managed DNS provider, which is a normal and often"
                        " healthy setup for reliability."
                    ),
                    impact=(
                        "This is informational, but it tells attackers which provider to study if"
                        " they are looking for misconfigurations."
                    ),
                    remediation=[
                        "Keep registrar and DNS provider access protected with MFA.",
                        "Review DNS changes periodically for anything unexpected.",
                    ],
                    evidence={"provider": "Google Cloud DNS"},
                ),
            ],
        ),
        "subdomains": ModuleResult(
            name="subdomains",
            status=ModuleStatus.COMPLETE,
            note="Certificate transparency logs revealed a handful of branded subdomains.",
            data={
                "subdomains": [
                    {
                        "name": "staging.demo.threatlens.io",
                        "first_seen": "2026-02-18T14:12:00+00:00",
                        "last_seen": "2026-04-02T09:20:00+00:00",
                        "expired_cert_reference": False,
                    },
                    {
                        "name": "legacy-billing.demo.threatlens.io",
                        "first_seen": "2025-11-07T12:45:00+00:00",
                        "last_seen": "2026-03-29T17:02:00+00:00",
                        "expired_cert_reference": True,
                    },
                ],
                "count": 2,
            },
            findings=[
                _finding(
                    title="Staging subdomain is visible in certificate logs",
                    category="subdomains",
                    severity=Severity.INFO,
                    description=(
                        "A staging environment appears in public certificate transparency data,"
                        " which means outsiders can discover it with very little effort."
                    ),
                    impact=(
                        "Staging systems often have weaker passwords, older code, or less"
                        " restrictive access controls than production systems."
                    ),
                    remediation=[
                        "Restrict staging access to employees or VPN users only.",
                        "Remove public DNS or certificate exposure for non-public environments.",
                    ],
                    evidence={"subdomain": "staging.demo.threatlens.io"},
                )
            ],
        ),
        "ssl_tls": ModuleResult(
            name="ssl_tls",
            status=ModuleStatus.COMPLETE,
            note="Primary certificate is current, but a legacy billing host surfaced a critical issue.",
            data={
                "issuer": {"organizationName": "Let's Encrypt"},
                "subject": {"commonName": "demo.threatlens.io"},
                "sans": ["demo.threatlens.io", "www.demo.threatlens.io"],
                "protocol_version": "TLSv1.3",
                "expires_at": "2026-06-20T00:00:00+00:00",
                "days_until_expiry": 72,
                "legacy_subdomain_expiry": "2026-03-12T00:00:00+00:00",
            },
            findings=[
                _finding(
                    title="Expired SSL certificate on legacy billing subdomain",
                    category="ssl_tls",
                    severity=Severity.CRITICAL,
                    description=(
                        "The fictional billing host `legacy-billing.demo.threatlens.io` is still"
                        " tied to an expired certificate."
                    ),
                    impact=(
                        "Expired certificates train users to click through warnings and can signal"
                        " that a sensitive legacy system is no longer maintained."
                    ),
                    remediation=[
                        "Confirm whether the billing subdomain is still needed.",
                        "If it is active, replace the expired certificate immediately.",
                        "If it is retired, remove its DNS records and decommission the host cleanly.",
                    ],
                    evidence={"subdomain": "legacy-billing.demo.threatlens.io", "expired_on": "2026-03-12"},
                )
            ],
        ),
        "email_security": ModuleResult(
            name="email_security",
            status=ModuleStatus.COMPLETE,
            note="Mail posture is the weakest part of the demo company's public attack surface.",
            data={
                "spf": {
                    "present": True,
                    "record_value": "v=spf1 include:_spf.google.com ~all",
                    "policy": "~all",
                    "risk_level": "medium",
                    "explanation": "SPF is present but only in softfail mode.",
                },
                "dmarc": {
                    "present": False,
                    "record_value": None,
                    "policy": None,
                    "risk_level": "critical",
                    "explanation": "No DMARC record was discovered.",
                },
                "dkim": [
                    {
                        "selector": "google",
                        "present": True,
                        "record_value": "v=DKIM1; k=rsa; p=demo-key",
                        "policy": "dkim",
                        "risk_level": "low",
                        "explanation": "Google Workspace DKIM selector detected.",
                    }
                ],
            },
            findings=[
                _finding(
                    title="No DMARC policy configured",
                    category="email_security",
                    severity=Severity.CRITICAL,
                    description=(
                        "The domain has no DMARC policy, which means inbox providers do not have"
                        " a clear instruction for rejecting fake emails sent in the company's name."
                    ),
                    impact=(
                        "Attackers can impersonate the business in phishing messages, invoice scams,"
                        " and account-reset attacks with far less resistance."
                    ),
                    remediation=[
                        "Publish a DMARC record at `_dmarc.demo.threatlens.io`.",
                        "Start with `p=none` to monitor traffic safely.",
                        "Move to `p=quarantine` or `p=reject` after validating legitimate senders.",
                    ],
                    evidence={"host": "_dmarc.demo.threatlens.io"},
                ),
                _finding(
                    title="SPF policy uses softfail",
                    category="email_security",
                    severity=Severity.MEDIUM,
                    description=(
                        "The SPF record ends with `~all`, which is softer than a fully enforced"
                        " policy."
                    ),
                    impact=(
                        "Softfail gives mail providers a hint, but it does not shut down spoofed"
                        " messages as strongly as a hard-fail policy."
                    ),
                    remediation=[
                        "Audit every legitimate email sender for the domain.",
                        "Update the SPF record to include only approved services.",
                        "Change `~all` to `-all` once the sender list is accurate.",
                    ],
                    evidence={"spf_record": "v=spf1 include:_spf.google.com ~all"},
                ),
                _finding(
                    title="DKIM is enabled for Google Workspace",
                    category="email_security",
                    severity=Severity.INFO,
                    description=(
                        "A DKIM signing key is present for the demo company's Google Workspace"
                        " mail flow."
                    ),
                    impact=(
                        "This is a helpful positive control because it allows recipient systems to"
                        " verify that some outbound messages are authentic."
                    ),
                    remediation=[
                        "Keep DKIM enabled for all primary sending platforms.",
                        "Rotate signing keys periodically as part of email hygiene.",
                    ],
                    evidence={"selector": "google"},
                ),
            ],
        ),
        "headers": ModuleResult(
            name="headers",
            status=ModuleStatus.COMPLETE,
            note="The web app redirects to HTTPS but several browser hardening headers are missing.",
            data={
                "https": {
                    "status_code": 200,
                    "headers": {
                        "server": "nginx/1.18.0",
                        "x-powered-by": "PHP/8.0.28",
                    },
                    "error": None,
                },
                "http": {
                    "status_code": 301,
                    "headers": {"location": "https://demo.threatlens.io"},
                    "error": None,
                },
                "redirects_to_https": True,
            },
            findings=[
                _finding(
                    title="HSTS is missing",
                    category="headers",
                    severity=Severity.HIGH,
                    description=(
                        "The site does not publish an HSTS header, so browsers are not told to"
                        " automatically insist on HTTPS on future visits."
                    ),
                    impact=(
                        "Without HSTS, users are more exposed to downgrade tricks and first-visit"
                        " interception attempts on insecure networks."
                    ),
                    remediation=[
                        "Enable the `Strict-Transport-Security` header on the primary site.",
                        "Start with a conservative max-age and expand after validation.",
                        "Include subdomains only after confirming every public host supports HTTPS.",
                    ],
                    evidence={"header": "strict-transport-security"},
                ),
                _finding(
                    title="Content-Security-Policy is missing",
                    category="headers",
                    severity=Severity.MEDIUM,
                    description=(
                        "The site does not publish a Content Security Policy to limit what scripts"
                        " and assets the browser should trust."
                    ),
                    impact=(
                        "Missing CSP makes browser-based attacks like malicious script injection"
                        " easier to exploit if another weakness is present."
                    ),
                    remediation=[
                        "Inventory the scripts, fonts, and domains the site truly needs.",
                        "Deploy a baseline `Content-Security-Policy` in report-only mode first.",
                        "Move to an enforced policy once violations are reviewed.",
                    ],
                    evidence={"header": "content-security-policy"},
                ),
                _finding(
                    title="Referrer-Policy is missing",
                    category="headers",
                    severity=Severity.LOW,
                    description=(
                        "The site does not define a referrer policy, so browsers may send more URL"
                        " information than necessary when users click away."
                    ),
                    impact=(
                        "That can leak internal paths or marketing parameters to third parties."
                    ),
                    remediation=[
                        "Set `Referrer-Policy: strict-origin-when-cross-origin` or a stricter option.",
                        "Retest the user journey to confirm analytics still work as expected.",
                    ],
                    evidence={"header": "referrer-policy"},
                ),
                _finding(
                    title="HTTP redirects correctly to HTTPS",
                    category="headers",
                    severity=Severity.INFO,
                    description=(
                        "The demo site does send visitors from HTTP to HTTPS automatically, which"
                        " is a healthy baseline control."
                    ),
                    impact=(
                        "This reduces the chance that routine visitors stay on an insecure version"
                        " of the site."
                    ),
                    remediation=[
                        "Keep the redirect in place.",
                        "Pair it with HSTS for stronger browser-side enforcement.",
                    ],
                    evidence={"location": "https://demo.threatlens.io"},
                ),
            ],
        ),
        "open_ports": ModuleResult(
            name="open_ports",
            status=ModuleStatus.COMPLETE,
            note="One legacy service is deliberately exposed in the demo storyline.",
            data={
                "ip_address": "203.0.113.42",
                "ports": [21, 443],
                "services": [
                    {
                        "port": 21,
                        "transport": "tcp",
                        "product": "vsftpd",
                        "version": "3.0.3",
                        "banner": "220 Demo retail file transfer service ready.",
                        "vulns": [],
                    }
                ],
                "hostnames": [DEMO_DOMAIN],
            },
            findings=[
                _finding(
                    title="FTP service is exposed to the internet",
                    category="open_ports",
                    severity=Severity.HIGH,
                    description=(
                        "Port 21 is open and running FTP, a legacy file transfer service that is"
                        " commonly targeted because it is often weakly protected."
                    ),
                    impact=(
                        "Attackers may attempt password guessing, intercept poorly secured transfers,"
                        " or use the service as a foothold into older business workflows."
                    ),
                    remediation=[
                        "Remove public FTP access if it is no longer required.",
                        "Replace it with SFTP or another modern encrypted transfer method.",
                        "If it must remain, lock it behind a VPN or allowlist trusted source IPs.",
                    ],
                    evidence={"port": 21, "service": "FTP"},
                )
            ],
        ),
        "tech_stack": ModuleResult(
            name="tech_stack",
            status=ModuleStatus.COMPLETE,
            note="The public site leaks enough technology detail to give attackers useful clues.",
            data={
                "server": "nginx/1.18.0",
                "x_powered_by": "PHP/8.0.28",
                "generator": "WordPress 6.1.4",
                "technologies": ["nginx", "wordpress", "php"],
            },
            findings=[
                _finding(
                    title="WordPress admin login is publicly reachable",
                    category="tech_stack",
                    severity=Severity.HIGH,
                    description=(
                        "The standard WordPress login path is exposed, making it very easy for an"
                        " attacker to identify the CMS and start testing credentials."
                    ),
                    impact=(
                        "A visible admin portal can become the front door for password spraying,"
                        " reused credentials, or plugin-targeted attacks."
                    ),
                    remediation=[
                        "Restrict `/wp-login.php` and `/wp-admin` behind MFA, SSO, or an IP allowlist.",
                        "Use a Web Application Firewall for login-rate protection.",
                        "Audit user accounts and remove any that are no longer needed.",
                    ],
                    evidence={"path": "/wp-login.php"},
                ),
                _finding(
                    title="Outdated WordPress version appears to be disclosed",
                    category="tech_stack",
                    severity=Severity.MEDIUM,
                    description=(
                        "The public site appears to reveal an older WordPress version in page or"
                        " header metadata."
                    ),
                    impact=(
                        "Version disclosure gives attackers a shortcut when matching your stack to"
                        " public vulnerabilities or unpatched plugins."
                    ),
                    remediation=[
                        "Update WordPress core, themes, and plugins to the latest supported versions.",
                        "Remove generator tags and version banners from public responses where possible.",
                    ],
                    evidence={"generator": "WordPress 6.1.4"},
                ),
                _finding(
                    title="Server version disclosure in response headers",
                    category="tech_stack",
                    severity=Severity.LOW,
                    description=(
                        "The site advertises server and runtime version details through public"
                        " headers like `Server` and `X-Powered-By`."
                    ),
                    impact=(
                        "These details reduce attacker guesswork and can speed up targeted probing."
                    ),
                    remediation=[
                        "Strip or generalize version-bearing headers at the reverse proxy.",
                        "Retain detailed version information only in internal monitoring systems.",
                    ],
                    evidence={"server": "nginx/1.18.0", "x-powered-by": "PHP/8.0.28"},
                ),
            ],
        ),
    }


async def run_demo_module(module_name: str) -> ModuleResult:
    """Return a demo module result after a realistic artificial delay."""

    modules = build_demo_modules()
    await asyncio.sleep(DEMO_MODULE_DELAYS.get(module_name, 0.75))
    return modules[module_name].model_copy(deep=True)


def write_demo_report_fixture(payload: dict) -> None:
    """Utility used only for maintaining the JSON fixture content."""

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    DEMO_REPORT_FIXTURE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
