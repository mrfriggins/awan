"""Strengthened assessment: knowledge/scoring, live check suite, rich reports."""
import datetime as dt

import httpx
import pytest

from eve.analysis import knowledge as kb
from eve.domain.enums import Confidence, OperationState, Severity
from eve.reporting.reporter import render_markdown
from eve.tools.live import client as live_client
from eve.tools.live import signatures as sg
from eve.tools.live.client import SafeHttpClient


# ---------------- knowledge / scoring ----------------
def test_knowledge_enrich_and_severity():
    f = kb.enrich({"check_id": "cors_wildcard_credentials"})
    assert f["cwe"] == "CWE-942"
    assert f["severity"] == "HIGH"
    assert f["references"]


def test_risk_scoring_scales_with_confidence():
    assert kb.risk_score(7.5, Confidence.CONFIRMED) == 7.5
    assert kb.risk_score(7.5, Confidence.LOW) < 7.5
    assert kb.risk_score(7.5, Confidence.FALSE_POSITIVE) == 0.0


def test_severity_bands():
    assert kb.severity_from_cvss(9.5) == Severity.CRITICAL
    assert kb.severity_from_cvss(7.0) == Severity.HIGH
    assert kb.severity_from_cvss(4.0) == Severity.MEDIUM
    assert kb.severity_from_cvss(1.0) == Severity.LOW
    assert kb.severity_from_cvss(0) == Severity.INFO


# ---------------- live check suite ----------------
def test_cookie_checks():
    out = sg.analyze_cookies(["sid=x; Path=/"], is_https=True)
    assert set(out) == {"cookie_insecure", "cookie_no_httponly", "cookie_no_samesite"}


def test_cors_wildcard_with_credentials():
    assert sg.analyze_cors({"access-control-allow-origin": "*",
                            "access-control-allow-credentials": "true"}) == \
        ["cors_wildcard_credentials"]


def test_dangerous_methods():
    checks, dangerous = sg.analyze_methods("GET, POST, PUT, TRACE")
    assert checks == ["http_dangerous_methods"]
    assert set(dangerous) == {"PUT", "TRACE"}


def test_tls_expiry():
    past = "Jan 01 00:00:00 2000 GMT"
    assert sg.analyze_tls({"notAfter": past}) == ["tls_expired"]


def test_sensitive_body_conservative():
    assert sg.classify_sensitive_body("/.git/config", 200, "[core]\nrepo") is True
    assert sg.classify_sensitive_body("/.git/config", 200, "<html>ok</html>") is False
    assert sg.classify_sensitive_body("/x", 404, "[core]") is False


# ---------------- rich report on a sim run ----------------
def test_report_has_scoring_and_markdown(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    snap = c.run_to_completion(snap.id)
    r = snap.report
    assert r.executive_summary and r.severity_breakdown
    assert r.risk_score > 0
    assert any(f.cwe for f in r.findings)
    assert any(f.risk_score > 0 for f in r.findings)
    md = render_markdown(r)
    assert "# Security Assessment Report" in md
    assert "## Executive summary" in md
    assert "## Findings" in md
    assert "Remediation:" in md


# ---------------- live e2e exercising the expanded suite ----------------
def _rich_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if request.method == "OPTIONS":
        return httpx.Response(200, headers={"Allow": "GET, POST, PUT, DELETE"})
    if path == "/.git/config":
        return httpx.Response(200, text="[core]\n\trepositoryformatversion = 0")
    if path in ("/robots.txt", "/.well-known/security.txt"):
        return httpx.Response(404, text="")
    if path.endswith((".zip", ".bak", ".php", "/entries", "/health", ".xml")):
        return httpx.Response(404, text="")
    return httpx.Response(200, headers={
        "Server": "nginx/1.18.0",
        "Set-Cookie": "sid=abc; Path=/",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }, text="<html>ok</html>")


@pytest.fixture
def rich_live_engine(engine, monkeypatch):
    monkeypatch.setenv("EVE_ALLOW_LIVE", "true")
    monkeypatch.setenv("EVE_LIVE_ALLOW_PRIVATE", "true")
    monkeypatch.setattr(live_client.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(SafeHttpClient, "tls_certificate", lambda self, h, p=443: {})
    engine.controller.live_transport = httpx.MockTransport(_rich_handler)
    engine.authorize_target(actor="operator", target="scanme.example")
    return engine


def test_live_full_assessment_findings(rich_live_engine):
    c = rich_live_engine.controller
    snap = c.create_operation(actor="operator", goal="full assessment",
                              targets=["scanme.example"], mode="live")
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED
    titles = {f.title for f in snap.findings}
    checks = {f.meta.get("check_id") for f in snap.findings}
    assert "cors_wildcard_credentials" in checks
    assert "http_dangerous_methods" in checks
    assert "exposed_sensitive_path" in checks
    assert any(c_ and c_.startswith("cookie_") for c_ in checks)
    assert "outdated_software" in checks
    # confirmed high-risk finding present, report scored
    confirmed = [f for f in snap.findings if f.confidence == Confidence.CONFIRMED]
    assert confirmed
    assert snap.report.risk_score >= 7.0  # CORS-with-credentials is high
    assert "A05:2021 Security Misconfiguration" in snap.report.owasp_coverage
