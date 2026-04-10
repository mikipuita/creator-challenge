"""Router for starting and orchestrating DomainVitals scans."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Awaitable, Callable, Dict
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, Request

from app.config import Settings, get_settings
from app.models.scan import ModuleResult, ModuleStatus, ScanLifecycle, ScanRequest, ScanResult
from app.services.ai_reporter import generate_ai_report
from app.services.demo_mode import build_demo_risk_score, is_demo_scan, run_demo_module
from app.services.dns_recon import run_dns_recon
from app.services.email_security import run_email_security
from app.services.header_analysis import run_header_analysis
from app.services.port_scan import run_port_scan
from app.services.risk_scorer import calculate_risk_score
from app.services.ssl_check import run_ssl_check
from app.services.subdomain_enum import run_subdomain_enum
from app.services.tech_fingerprint import run_tech_fingerprint
from app.state import SCAN_STORE
from app.utils.helpers import SimpleRateLimiter, validate_domain_input

router = APIRouter(tags=["scan"])
rate_limiter = SimpleRateLimiter(limit=8, window_seconds=60)
MODULE_NAMES = (
    "dns",
    "subdomains",
    "ssl_tls",
    "email_security",
    "headers",
    "open_ports",
    "tech_stack",
)


def _build_initial_modules() -> Dict[str, ModuleResult]:
    """Create the default per-module scan status structure."""

    return {
        module_name: ModuleResult(name=module_name, status=ModuleStatus.PENDING)
        for module_name in MODULE_NAMES
    }


async def _run_single_module(
    scan_result: ScanResult,
    module_name: str,
    operation: Callable[[], Awaitable[ModuleResult]],
) -> None:
    """Execute a module and write its result back into the scan store."""

    started_at = datetime.utcnow()
    scan_result.modules[module_name].status = ModuleStatus.SCANNING
    scan_result.modules[module_name].started_at = started_at
    scan_result.updated_at = started_at
    try:
        result = await operation()
        result.name = module_name
        result.started_at = started_at
        result.completed_at = datetime.utcnow()
        scan_result.modules[module_name] = result
    except Exception as exc:
        scan_result.modules[module_name] = ModuleResult(
            name=module_name,
            status=ModuleStatus.ERROR,
            findings=[],
            data={},
            error=str(exc),
            started_at=started_at,
            completed_at=datetime.utcnow(),
        )
    finally:
        scan_result.updated_at = datetime.utcnow()


async def _run_scan_pipeline(
    scan_id: str,
    domain: str,
    settings: Settings,
) -> None:
    """Run all recon modules in parallel, then score and summarize the results."""

    scan_result = SCAN_STORE[scan_id]
    try:
        await asyncio.gather(
            _run_single_module(scan_result, "dns", lambda: run_dns_recon(domain)),
            _run_single_module(
                scan_result,
                "subdomains",
                lambda: run_subdomain_enum(domain, settings.request_timeout_seconds),
            ),
            _run_single_module(scan_result, "ssl_tls", lambda: run_ssl_check(domain)),
            _run_single_module(scan_result, "email_security", lambda: run_email_security(domain)),
            _run_single_module(
                scan_result,
                "headers",
                lambda: run_header_analysis(domain, settings.request_timeout_seconds),
            ),
            _run_single_module(
                scan_result,
                "open_ports",
                lambda: run_port_scan(
                    domain,
                    settings.request_timeout_seconds,
                    settings.shodan_api_key.get_secret_value()
                    if settings.shodan_api_key
                    else None,
                ),
            ),
            _run_single_module(
                scan_result,
                "tech_stack",
                lambda: run_tech_fingerprint(domain, settings.request_timeout_seconds),
            ),
        )

        scan_result.findings = [
            finding
            for module in scan_result.modules.values()
            for finding in module.findings
        ]
        scan_result.risk_score = calculate_risk_score(scan_result.modules)
        scan_result.report = await asyncio.to_thread(
            generate_ai_report,
            scan_result,
            api_key=(
                settings.openai_api_key.get_secret_value()
                if settings.openai_api_key
                else None
            ),
            model=settings.openai_model,
            max_findings=settings.max_report_findings,
        )
        scan_result.status = ScanLifecycle.COMPLETED
        scan_result.completed_at = datetime.utcnow()
        scan_result.updated_at = scan_result.completed_at
    except Exception as exc:
        scan_result.status = ScanLifecycle.FAILED
        scan_result.updated_at = datetime.utcnow()
        scan_result.completed_at = scan_result.updated_at
        scan_result.modules["reporting"] = ModuleResult(
            name="reporting",
            status=ModuleStatus.ERROR,
            error=str(exc),
            completed_at=scan_result.updated_at,
        )


async def _run_demo_scan_pipeline(
    scan_id: str,
    domain: str,
    settings: Settings,
) -> None:
    """Run the pre-built demo scan with staggered module timing."""

    scan_result = SCAN_STORE[scan_id]
    try:
        await asyncio.gather(
            *(
                _run_single_module(
                    scan_result,
                    module_name,
                    lambda module_name=module_name: run_demo_module(module_name),
                )
                for module_name in MODULE_NAMES
            )
        )

        scan_result.findings = [
            finding
            for module in scan_result.modules.values()
            for finding in module.findings
        ]
        scan_result.risk_score = build_demo_risk_score()
        scan_result.report = await asyncio.to_thread(
            generate_ai_report,
            scan_result,
            api_key=(
                settings.openai_api_key.get_secret_value()
                if settings.openai_api_key
                else None
            ),
            model=settings.openai_model,
            max_findings=settings.max_report_findings,
            demo_mode=True,
        )
        scan_result.status = ScanLifecycle.COMPLETED
        scan_result.completed_at = datetime.utcnow()
        scan_result.updated_at = scan_result.completed_at
    except Exception as exc:
        scan_result.status = ScanLifecycle.FAILED
        scan_result.updated_at = datetime.utcnow()
        scan_result.completed_at = scan_result.updated_at
        scan_result.modules["reporting"] = ModuleResult(
            name="reporting",
            status=ModuleStatus.ERROR,
            error=str(exc),
            completed_at=scan_result.updated_at,
        )


@router.post("/scan")
async def create_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create a new scan request and return immediately with a scan identifier."""

    client_host = request.client.host if request.client else "anonymous"
    rate_limiter.check(client_host)
    domain = validate_domain_input(payload.domain)
    scan_id = str(uuid4())
    scan_result = ScanResult(scan_id=scan_id, domain=domain, modules=_build_initial_modules())
    SCAN_STORE[scan_id] = scan_result
    if is_demo_scan(domain, settings.demo_mode):
        background_tasks.add_task(_run_demo_scan_pipeline, scan_id, domain, settings)
    else:
        background_tasks.add_task(_run_scan_pipeline, scan_id, domain, settings)
    return {"scan_id": scan_id, "status": ScanLifecycle.SCANNING}
