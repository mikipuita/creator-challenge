"""Router for retrieving scan progress and results."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.models.scan import ScanResult
from app.state import SCAN_STORE

router = APIRouter(tags=["results"])


@router.get("/results/{scan_id}", response_model=ScanResult)
async def get_results(scan_id: str) -> ScanResult:
    """Return the current state of a scan result."""

    scan_result = SCAN_STORE.get(scan_id)
    if scan_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan found for the supplied scan_id.",
        )
    return scan_result
