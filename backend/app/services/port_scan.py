"""Shodan-backed open port enumeration."""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List, Optional

import httpx

from app.models.scan import Finding, ModuleResult, ModuleStatus, Severity

RISKY_PORTS = {
    21: ("FTP", Severity.HIGH),
    23: ("Telnet", Severity.CRITICAL),
    139: ("NetBIOS", Severity.HIGH),
    445: ("SMB", Severity.CRITICAL),
    3389: ("RDP", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
}


def _resolve_ip(domain: str) -> str:
    """Resolve a domain to a single IPv4 address for Shodan lookups."""

    return socket.gethostbyname(domain)


async def run_port_scan(
    domain: str,
    timeout_seconds: float,
    shodan_api_key: Optional[str],
) -> ModuleResult:
    """Query the Shodan host API for open ports and services."""

    try:
        ip_address = await asyncio.to_thread(_resolve_ip, domain)
    except OSError as exc:
        return ModuleResult(
            name="open_ports",
            status=ModuleStatus.ERROR,
            findings=[],
            data={},
            error=f"Failed to resolve domain for port scan: {exc}",
        )

    if not shodan_api_key:
        return ModuleResult(
            name="open_ports",
            status=ModuleStatus.SKIPPED,
            findings=[],
            data={"ip_address": ip_address, "ports": []},
            note="Shodan API key not configured. Open port scan skipped.",
        )

    url = f"https://api.shodan.io/shodan/host/{ip_address}"
    params = {"key": shodan_api_key, "minify": "false"}

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            payload: Dict[str, Any] = response.json()
    except httpx.HTTPStatusError as exc:
        return ModuleResult(
            name="open_ports",
            status=ModuleStatus.ERROR,
            findings=[],
            data={"ip_address": ip_address},
            error=f"Shodan request failed with status {exc.response.status_code}.",
        )
    except (httpx.HTTPError, ValueError) as exc:
        return ModuleResult(
            name="open_ports",
            status=ModuleStatus.ERROR,
            findings=[],
            data={"ip_address": ip_address},
            error=f"Shodan lookup failed: {exc}",
        )

    findings: List[Finding] = []
    services = []
    for service in payload.get("data", []):
        port = int(service.get("port"))
        product = service.get("product")
        version = service.get("version")
        vulns = sorted((service.get("vulns") or {}).keys())
        services.append(
            {
                "port": port,
                "transport": service.get("transport"),
                "product": product,
                "version": version,
                "banner": service.get("data"),
                "vulns": vulns,
            }
        )

        if port in RISKY_PORTS:
            service_name, severity = RISKY_PORTS[port]
            findings.append(
                Finding(
                    title=f"Risky internet-facing service detected on port {port}",
                    category="open_ports",
                    severity=severity,
                    description=(
                        f"Shodan reports that {service_name} is exposed to the public internet"
                        f" on port {port}."
                    ),
                    impact=(
                        "Remote access and legacy file-sharing protocols attract attackers and"
                        " often become the first path into a business environment."
                    ),
                    remediation=[
                        "Remove the service from the public internet if possible.",
                        "Restrict access with a VPN, IP allowlist, or hardened bastion host.",
                    ],
                    evidence={"port": port, "product": product, "version": version},
                )
            )

        if vulns:
            findings.append(
                Finding(
                    title=f"Known vulnerabilities associated with port {port}",
                    category="open_ports",
                    severity=Severity.HIGH,
                    description=(
                        "Shodan associated public vulnerability identifiers with an exposed"
                        " service on this host."
                    ),
                    impact=(
                        "Known internet-facing vulnerabilities materially increase the chance"
                        " of automated exploitation."
                    ),
                    remediation=[
                        "Patch or upgrade the affected service immediately.",
                        "Validate the exposure externally after remediation.",
                    ],
                    evidence={"port": port, "vulnerabilities": vulns[:10]},
                )
            )

    return ModuleResult(
        name="open_ports",
        status=ModuleStatus.COMPLETE,
        findings=findings,
        data={
            "ip_address": ip_address,
            "ports": payload.get("ports", []),
            "services": services,
            "hostnames": payload.get("hostnames", []),
        },
        note="Open port review completed using Shodan.",
    )
