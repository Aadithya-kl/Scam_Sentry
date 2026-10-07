import os
import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

RATE_LIMITED_PATHS = frozenset({"/predict", "/scan-url", "/scan-page"})


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    """Per-client sliding-window rate limiter (in-memory, per process).

    Only the analysis endpoints are limited; /health, /ready and /config are not.
    Limit is configurable via RATE_LIMIT_PER_MINUTE. Also attaches basic
    security headers to every response.
    """

    def __init__(self, app, max_requests: int | None = None, window_seconds: int = 60, max_tracked_clients: int = 10_000):
        super().__init__(app)
        env_limit = os.environ.get("RATE_LIMIT_PER_MINUTE")
        self.max_requests = int(env_limit) if env_limit else (max_requests or 60)
        self.window_seconds = window_seconds
        self.max_tracked_clients = max_tracked_clients
        self.request_records: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, now: float) -> None:
        # Bound memory: drop clients with no requests inside the window.
        if len(self.request_records) <= self.max_tracked_clients:
            return
        stale = [ip for ip, q in self.request_records.items() if not q or now - q[-1] >= self.window_seconds]
        for ip in stale:
            del self.request_records[ip]

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and request.url.path in RATE_LIMITED_PATHS:
            client_ip = request.client.host if request.client else "unknown"
            now = time.time()
            q = self.request_records[client_ip]
            while q and now - q[0] >= self.window_seconds:
                q.popleft()

            if len(q) >= self.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={"error": {"code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests. Please try again later."}},
                    headers={"Retry-After": str(self.window_seconds)},
                )
            q.append(now)
            self._prune(now)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
