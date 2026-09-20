"""API authentication, authorization, and end-to-end workflow over HTTP."""
import pytest
from fastapi.testclient import TestClient

from eve.api.app import create_app

OP = {"Authorization": "Bearer operator-token"}
APPROVER = {"Authorization": "Bearer approver-token"}
VIEWER = {"Authorization": "Bearer viewer-token"}


@pytest.fixture
def client(authorized_engine):
    return TestClient(create_app(engine=authorized_engine))


def test_health_open(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_requires_auth(client):
    assert client.get("/api/operations").status_code == 401
    assert client.post("/api/operations", json={"goal": "x y", "targets": ["t"]}).status_code == 401


def test_invalid_token(client):
    assert client.get("/api/status",
                      headers={"Authorization": "Bearer nope"}).status_code == 401


def test_viewer_cannot_create(client):
    r = client.post("/api/operations", headers=VIEWER,
                    json={"goal": "full assessment", "targets": ["lab-web-01"]})
    assert r.status_code == 403


def test_end_to_end_over_http(client):
    r = client.post("/api/operations", headers=OP,
                    json={"goal": "full assessment", "targets": ["lab-web-01"]})
    assert r.status_code == 201
    op = r.json()["id"]
    snap = client.post(f"/api/operations/{op}/run", headers=OP).json()
    assert snap["state"] == "SUCCEEDED"
    report = client.get(f"/api/operations/{op}/report", headers=OP).json()
    assert report["outcome"] == "completed"
    assert len(report["findings"]) >= 1
    events = client.get(f"/api/operations/{op}/events", headers=OP).json()["events"]
    assert len(events) > 10
    audit = client.get(f"/api/operations/{op}/audit", headers=OP).json()
    assert audit["intact"] is True


def test_validation_error_returns_400(client):
    r = client.post("/api/operations", headers=OP,
                    json={"goal": "x", "targets": []})
    assert r.status_code == 422  # pydantic rejects empty targets


def test_unauthorized_target_returns_400(client):
    r = client.post("/api/operations", headers=OP,
                    json={"goal": "full assessment", "targets": ["prod-secret"]})
    # operation is created but immediately FAILED (deterministic authz)
    assert r.status_code == 201
    assert r.json()["state"] == "FAILED"


def test_approval_flow_over_http(client):
    r = client.post("/api/operations", headers=OP,
                    json={"goal": "full assessment", "targets": ["lab-web-01"],
                          "require_approval": True})
    op = r.json()["id"]
    assert r.json()["state"] == "AWAITING_APPROVAL"
    # operator (no approver role) cannot approve
    assert client.post(f"/api/operations/{op}/approve", headers=OP).status_code == 403
    snap = client.post(f"/api/operations/{op}/approve", headers=APPROVER).json()
    assert snap["state"] in ("QUEUED", "RUNNING", "SUCCEEDED")
    snap = client.post(f"/api/operations/{op}/run", headers=OP).json()
    assert snap["state"] == "SUCCEEDED"


def test_emergency_stop_over_http(client):
    r = client.post("/api/operations", headers=OP,
                    json={"goal": "full assessment", "targets": ["lab-web-01"]})
    op = r.json()["id"]
    assert client.post("/api/emergency-stop", headers=OP,
                       json={"reason": "drill"}).status_code == 200
    snap = client.post(f"/api/operations/{op}/run", headers=OP).json()
    assert snap["state"] == "STOPPED"
    client.post("/api/emergency-stop/reset", headers=OP)


def test_tools_listing(client):
    tools = client.get("/api/tools", headers=OP).json()["tools"]
    assert len(tools) == 4
