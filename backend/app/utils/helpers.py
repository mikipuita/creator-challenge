"""Validation and support helpers used throughout the DomainVitals backend."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict

from fastapi import HTTPException, status

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
)


def normalize_domain(domain: str) -> str:
    """Normalize a user-supplied domain into a lowercase host string."""

    candidate = domain.strip().lower()
    candidate = re.sub(r"^https?://", "", candidate)
    candidate = candidate.split("/")[0].split(":")[0]
    return candidate.rstrip(".")


def validate_domain_input(domain: str) -> str:
    """Validate a domain name and reject unsafe or non-public targets."""

    candidate = normalize_domain(domain)
    if candidate in {"localhost", "localhost.localdomain"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Localhost is not a valid public scan target.",
        )

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = None

    if ip is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="IP addresses are not allowed. Please submit a public domain.",
        )

    if not DOMAIN_PATTERN.match(candidate):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please provide a valid public domain such as example.com.",
        )

    labels = candidate.split(".")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Domain labels cannot start or end with hyphens.",
        )

    if labels[-1].isdigit():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The submitted target must be a resolvable public hostname.",
        )

    try:
        resolved = {result[4][0] for result in socket.getaddrinfo(candidate, None)}
    except socket.gaierror:
        resolved = set()

    for ip_text in resolved:
        ip_value = ipaddress.ip_address(ip_text)
        if any(
            [
                ip_value.is_private,
                ip_value.is_loopback,
                ip_value.is_link_local,
                ip_value.is_multicast,
                ip_value.is_reserved,
            ]
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Domains that resolve to internal or non-public IP ranges are not allowed.",
            )

    return candidate


class SimpleRateLimiter:
    """Small in-memory sliding window limiter suitable for a demo API."""

    def __init__(self, limit: int = 10, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> None:
        """Record a hit and raise an error if the key exceeded its quota."""

        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many scan requests. Please wait a moment and try again.",
                )
            bucket.append(now)
