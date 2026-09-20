"""Live (online) recon: guardrails + a fully mocked end-to-end operation.

No real network is used. HTTP is served by an injected httpx.MockTransport and
DNS is monkeypatched, so these tests are hermetic and safe in CI.
"""
import httpx
import pytest

from eve.domain.enums import Confidence, OperationState
from eve.tools.live import client as live_client
from eve.tools.live.client import LiveNetworkError, SafeHttpClient


# ---------------------------- guardrails ----------------------------
def test_live_disabled_by_default(monkeypatch):
    monkeypatch.delenv("EVE_ALLOW_LIVE", raising=False)
    with pytest.raises(LiveNetworkError, match="disabled"):
        SafeHttpClient().fetch("https://example.com")


def test_bad_scheme_refused(monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    with pytest.raises(LiveNetworkError, match="scheme"):
        SafeHttpClient().fetch("ftp://example.com")


def test_only_get_head(monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    with pytest.raises(LiveNetworkError, match="method"):
        SafeHttpClient().fetch("https://example.com", method="POST")


def test_private_ip_blocked(monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    monkeypatch.delenv("EVE_LIVE_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(live_client.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(LiveNetworkError, match="non-public"):
        SafeHttpClient().fetch("https://internal.local")


def test_metadata_ip_blocked(monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    monkeypatch.delenv("EVE_LIVE_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(live_client.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))])
    with pytest.raises(LiveNetworkError):
        SafeHttpClient().fetch("https://metadata.example")


def test_allowlist_enforced(monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    monkeypatch.setenv("EVE_LIVE_ALLOW_PRIVATE", "true")
    monkeypatch.setenv("EVE_LIVE_ALLOWED_HOSTS", "allowed.example")
    with pytest.raises(LiveNetworkError, match="not in EVE_LIVE_ALLOWED_HOSTS"):
        SafeHttpClient().fetch("https://blocked.example")


# ---------------------------- end to end ----------------------------
def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    headers = {"Server": "nginx/1.18.0"}  # outdated + missing security headers
    if path in ("/robots.txt", "/.well-known/security.txt"):
        return httpx.Response(404, text="")
    return httpx.Response(200, headers=headers, text="<html>ok</html>")


@pytest.fixture
def live_engine(engine, monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    monkeypatch.setenv("EVE_LIVE_ALLOW_PRIVATE", "true")  # skip DNS guard in test
    monkeypatch.setattr(live_client.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    # avoid real TLS sockets during config_analysis
    monkeypatch.setattr(SafeHttpClient, "tls_certificate", lambda self, h, p=443: {})
    engine.controller.live_transport = httpx.MockTransport(_handler)
    engine.authorize_target(actor="operator", target="scanme.example")
    return engine


def test_live_disabled_operation_fails_fast(authorized_engine, monkeypatch):
    monkeypatch.delenv("EVE_ALLOW_LIVE", raising=False)
    authorized_engine.authorize_target(actor="operator", target="scanme.example")
    snap = authorized_engine.controller.create_operation(
        actor="operator", goal="full assessment", targets=["scanme.example"],
        mode="live")
    assert snap.state == OperationState.FAILED
    assert any("live networking disabled" in e for e in snap.errors)


def test_live_end_to_end(live_engine):
    c = live_engine.controller
    snap = c.create_operation(actor="operator", goal="full assessment",
                              targets=["scanme.example"], mode="live")
    assert snap.state == OperationState.QUEUED
    assert all(s.tool_id.startswith("net.") for s in snap.plan.steps)
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED
    titles = {f.title for f in snap.findings}
    assert "Outdated nginx web server" in titles
    assert any("Strict-Transport-Security" in t for t in titles)
    # validation re-observed the same benign signals -> confirmed
    assert any(f.confidence == Confidence.CONFIRMED for f in snap.findings)
    ok, _ = c.audit.verify_chain(snap.id)
    assert ok


def test_live_requires_authorization(live_engine):
    c = live_engine.controller
    snap = c.create_operation(actor="operator", goal="full assessment",
                              targets=["not-authorized.example"], mode="live")
    assert snap.state == OperationState.FAILED  # deterministic authz denies
