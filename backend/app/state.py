"""In-memory state store used by the demo backend."""

from __future__ import annotations

from typing import Dict

from app.models.scan import ScanResult


SCAN_STORE: Dict[str, ScanResult] = {}
