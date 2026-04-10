"""Router for exporting a completed scan as a PDF report."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from app.models.scan import ScanLifecycle
from app.state import SCAN_STORE
from app.utils.pdf_generator import generate_fallback_pdf_report, generate_pdf_report

router = APIRouter(tags=["report"])


@router.get("/report/{scan_id}/pdf")
async def download_report(scan_id: str) -> Response:
    """Generate and return the PDF report for a completed scan."""

    scan_result = SCAN_STORE.get(scan_id)
    if scan_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan found for the supplied scan_id.",
        )
    if scan_result.status != ScanLifecycle.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The scan is not complete yet. Try again after processing finishes.",
        )

    try:
        pdf_bytes = await asyncio.to_thread(generate_pdf_report, scan_result)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        try:
            pdf_bytes = await asyncio.to_thread(
                generate_fallback_pdf_report,
                scan_result,
                str(exc),
            )
        except Exception as fallback_exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"PDF generation failed: {exc}; fallback export failed: {fallback_exc}",
            ) from fallback_exc

    filename = f"{scan_result.domain}-domainvitals-report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
