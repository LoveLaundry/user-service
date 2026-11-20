"""CORS must survive the middleware stack.

Production symptom this guards against: the login page failed with

    blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present

while the endpoint itself was healthy. The rate limiter was mounted OUTSIDE
CORSMiddleware, so a 429 short-circuited before any CORS header was written and
the browser reported a rate limit as a CORS failure. Because Starlette runs the
most recently added middleware first, CORS has to be added last.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from user_service.security import apply_security

PRODUCTION_ORIGIN = "https://system-lovelaundry-lk.vercel.app"


def _app(rate_limit: int = 300) -> FastAPI:
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    apply_security(app, rate_limit=rate_limit)
    return app


def test_cors_is_the_outermost_middleware():
    app = _app()
    assert app.user_middleware[0].cls.__name__ == "CORSMiddleware"


def test_preflight_allows_the_production_origin():
    client = TestClient(_app())
    response = client.options(
        "/ping",
        headers={
            "Origin": PRODUCTION_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == PRODUCTION_ORIGIN


def test_rate_limited_response_still_carries_cors_headers():
    """A 429 without ACAO is indistinguishable from a CORS failure in-browser."""
    client = TestClient(_app(rate_limit=1))
    headers = {"Origin": PRODUCTION_ORIGIN}

    assert client.get("/ping", headers=headers).status_code == 200
    limited = client.get("/ping", headers=headers)

    assert limited.status_code == 429
    assert limited.headers["access-control-allow-origin"] == PRODUCTION_ORIGIN


def test_production_origin_is_in_the_default_allowlist():
    """A missing ALLOWED_ORIGINS env var must not lock the live UI out."""
    from user_service.main import ALLOWED_ORIGINS

    assert PRODUCTION_ORIGIN in ALLOWED_ORIGINS
