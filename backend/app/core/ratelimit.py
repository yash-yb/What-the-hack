"""
Small in-memory sliding-window rate limiter.

Good enough for a single-process prototype (the master plan asks for basic limiting on
login and upload). Move the counters to Redis when the backend runs more than one worker.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> float | None:
        """Record one hit. Returns None when allowed, or seconds until the window frees up."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] >= self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return self.window_seconds - (now - bucket[0])
            bucket.append(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce(limiter: RateLimiter, key: str, what: str, enabled: bool = True) -> None:
    if not enabled:
        return
    retry_after = limiter.hit(key)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many {what} attempts. Try again in {int(retry_after) + 1} seconds.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
