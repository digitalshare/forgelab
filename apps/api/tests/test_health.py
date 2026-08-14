"""Smoke tests for the application factory and probes."""

from fastapi.testclient import TestClient

from forgelab_api.main import create_app

client = TestClient(create_app())


def test_liveness_needs_no_dependencies():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readiness_reports_each_dependency():
    """Readiness must answer even when Postgres and Redis are down."""
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert set(body["checks"]) == {"postgres", "redis"}
    assert isinstance(body["ready"], bool)


def test_openapi_schema_builds():
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["title"] == "ForgeLab API"
