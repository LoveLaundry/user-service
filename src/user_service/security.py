"""Security hardening middleware for User Service.

• SecurityHeadersMiddleware — injects strict response headers
• RateLimitMiddleware — sliding-window token bucket per client IP
• Insecure secret detection — health endpoint reports when defaults are active
"""
import time
import re
import hashlib
import ipaddress
import uuid
import os
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# A client-supplied correlation id is echoed back in `X-Request-Id`. It is
# attacker-controlled, so it is only trusted when it matches this shape —
# otherwise a caller could inject arbitrary bytes (including CR/LF) into the
# response headers and into whatever logs key off that header.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# Known production frontend origins. Mirrors the safe defaults in main.py so the
# API is never wide-open ("*") yet never fully locked down if CORS_ORIGINS is
# not injected by the platform.
DEFAULT_ALLOWED_ORIGINS = [
    "https://lovelaundry-manager.vercel.app",

    "https://system-lovelaundry-lk.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # HSTS is only honoured over TLS; sending it on a plain-HTTP response
        # is meaningless and locks out local development behind HTTPS.
        if _is_https(request):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        response.headers["X-Request-Id"] = _resolve_request_id(request)
        return response


def _is_https(request: Request) -> bool:
    """True when the request reached us over TLS.

    ``X-Forwarded-Proto`` is only consulted because this service is deployed
    behind a TLS-terminating proxy; when it is absent the socket scheme is
    authoritative.
    """
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        return forwarded.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _resolve_request_id(request: Request) -> str:
    """Return a safe correlation id for the response.

    A well-formed client value is preserved so a caller can correlate its own
    request with ours; anything else is replaced with a freshly generated id
    instead of being echoed verbatim.
    """
    supplied = request.headers.get("x-request-id", "")
    if supplied and _REQUEST_ID_RE.match(supplied):
        return supplied
    return _generate_req_id()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 300):
        super().__init__(app)
        self.limit = requests_per_minute
        self._buckets: dict[str, list[float]] = {}
        self._last_prune = time.time()

    async def dispatch(self, request: Request, call_next):
        key = _client_key(request)
        now = time.time()
        window_start = now - 60.0
        # Drop idle keys periodically; otherwise the dict keeps one entry per
        # distinct client IP for the process lifetime (unbounded memory growth).
        if now - self._last_prune >= 60.0:
            pruned = {}
            for bucket_key, stamps in self._buckets.items():
                live = [t for t in stamps if t >= window_start]
                if live:
                    pruned[bucket_key] = live
            self._buckets = pruned
            self._last_prune = now
        hits = [t for t in self._buckets.get(key, []) if t >= window_start]
        self._buckets[key] = hits
        if len(hits) >= self.limit:
            retry_after = max(1, int(60.0 - (now - min(hits))))
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded — try again shortly."},
                headers={"Retry-After": str(retry_after)},
            )
        self._buckets[key] = [*hits, now]
        return await call_next(request)


def _client_key(request: Request) -> str:
    """Return the bucket key for the caller.

    Behind the nginx reverse proxy every socket arrives from the proxy's own
    address, so ``request.client.host`` is the SAME value for every visitor —
    which turns the per-IP limit into a global limit and lets one client deny
    service to everybody. The forwarded client address is used instead, but
    only when the direct peer is a local/private address (i.e. a trusted
    reverse proxy). A service exposed directly therefore cannot be tricked
    into spoofing another client's bucket by setting the header itself.
    """
    peer = request.client.host if request.client else None
    if peer and _is_trusted_proxy(peer):
        forwarded = _forwarded_client_ip(request)
        if forwarded:
            return forwarded
    return peer or "unknown"


def _is_trusted_proxy(peer: str) -> bool:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def _forwarded_client_ip(request: Request) -> Optional[str]:
    """Extract the client address a trusted proxy recorded."""
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    # nginx appends the address it saw to whatever the caller sent, so the
    # RIGHT-most entry is the one it observed, not a client-supplied one.
    for candidate in reversed([part.strip() for part in forwarded.split(",")]):
        if candidate:
            return candidate
    return None


def _generate_req_id() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16]


def _resolve_origins() -> list[str]:
    # Honor both env names: the platform injects ALLOWED_ORIGINS while local
    # tooling historically used CORS_ORIGINS. main.py computes the same
    # ALLOWED_ORIGINS list from ALLOWED_ORIGINS — merging keeps both in effect.
    raw = ",".join(
        part
        for part in (os.getenv("CORS_ORIGINS", ""), os.getenv("ALLOWED_ORIGINS", ""))
        if part.strip()
    )
    configured = [
        o.strip()
        for o in raw.split(",")
        if o.strip() and o.strip() != "*"
    ]
    return list(dict.fromkeys(configured + list(DEFAULT_ALLOWED_ORIGINS)))


def apply_security(app: FastAPI, rate_limit: int = 300) -> None:
    """Mount CORS, security headers, and rate limiting on the FastAPI app."""
    from fastapi.middleware.cors import CORSMiddleware

    origins = _resolve_origins()
    # Order matters: Starlette runs the most recently added middleware first.
    # CORS is added LAST so it wraps the rate limiter and the security headers —
    # otherwise a 429 short-circuits before CORS and the browser reports the
    # rejected request as a CORS failure instead of a rate limit.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=rate_limit)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False if "*" in origins else True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ── Insecure-secret state tracking (for health endpoint) ─────────────────────
_jwt_insecure = False
_master_insecure = False


def mark_jwt_insecure() -> None:
    global _jwt_insecure
    _jwt_insecure = True


def mark_master_insecure() -> None:
    global _master_insecure
    _master_insecure = True


def insecure_flags() -> dict:
    return {
        "jwt_secret_uses_fallback": _jwt_insecure,
        "master_key_uses_fallback": _master_insecure,
    }