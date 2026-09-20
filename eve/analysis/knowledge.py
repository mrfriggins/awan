"""Assessment knowledge base + risk scoring.

Maps each check to CWE / OWASP Top-10 (2021) / a CVSS-ish base score and
authoritative references, so findings carry the context a professional report
needs. Nothing here contacts a network; it is a static rulebook that a live CVE
feed could later augment.
"""
from __future__ import annotations

from typing import Dict

from ..domain.enums import Confidence, Severity

# check_id -> metadata
KB: Dict[str, dict] = {
    "outdated_software": {
        "cwe": "CWE-1104", "owasp": "A06:2021 Vulnerable & Outdated Components",
        "cvss": 5.3,
        "references": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]},
    "missing_hsts": {
        "cwe": "CWE-319", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]},
    "missing_csp": {
        "cwe": "CWE-1021", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/CSP"]},
    "missing_xcto": {
        "cwe": "CWE-16", "owasp": "A05:2021 Security Misconfiguration", "cvss": 3.1,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"]},
    "missing_xfo": {
        "cwe": "CWE-1021", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"]},
    "missing_referrer_policy": {
        "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "cvss": 2.6,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"]},
    "missing_permissions_policy": {
        "cwe": "CWE-16", "owasp": "A05:2021 Security Misconfiguration", "cvss": 2.0,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"]},
    "clickjacking": {
        "cwe": "CWE-1021", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3,
        "references": ["https://owasp.org/www-community/attacks/Clickjacking"]},
    "cookie_insecure": {
        "cwe": "CWE-614", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"]},
    "cookie_no_httponly": {
        "cwe": "CWE-1004", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "references": ["https://owasp.org/www-community/HttpOnly"]},
    "cookie_no_samesite": {
        "cwe": "CWE-1275", "owasp": "A01:2021 Broken Access Control", "cvss": 4.3,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]},
    "cors_wildcard_credentials": {
        "cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration", "cvss": 7.5,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/CORS"]},
    "cors_wildcard": {
        "cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3,
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/CORS"]},
    "http_dangerous_methods": {
        "cwe": "CWE-650", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]},
    "server_version_disclosure": {
        "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "cvss": 3.1,
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]},
    "directory_listing": {
        "cwe": "CWE-548", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "references": ["https://owasp.org/www-community/vulnerabilities/Directory_indexing"]},
    "exposed_sensitive_path": {
        "cwe": "CWE-538", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5,
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]},
    "tls_expired": {
        "cwe": "CWE-298", "owasp": "A02:2021 Cryptographic Failures", "cvss": 7.4,
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]},
    "tls_expiring": {
        "cwe": "CWE-298", "owasp": "A02:2021 Cryptographic Failures", "cvss": 3.7,
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]},
    "missing_dmarc": {
        "cwe": "CWE-290", "owasp": "A07:2021 Identification & Authentication Failures",
        "cvss": 4.3,
        "references": ["https://dmarc.org/"]},
    "missing_spf": {
        "cwe": "CWE-290", "owasp": "A07:2021 Identification & Authentication Failures",
        "cvss": 4.3,
        "references": ["https://www.rfc-editor.org/rfc/rfc7208"]},
}

_CONF_WEIGHT = {
    Confidence.UNVERIFIED: 0.4, Confidence.LOW: 0.6, Confidence.MEDIUM: 0.8,
    Confidence.HIGH: 0.95, Confidence.CONFIRMED: 1.0, Confidence.FALSE_POSITIVE: 0.0,
}


def severity_from_cvss(cvss: float) -> Severity:
    if cvss <= 0:
        return Severity.INFO
    if cvss < 4.0:
        return Severity.LOW
    if cvss < 7.0:
        return Severity.MEDIUM
    if cvss < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def risk_score(cvss: float, confidence: Confidence) -> float:
    """0-10 risk = CVSS base weighted by evidence confidence."""
    return round(cvss * _CONF_WEIGHT.get(confidence, 0.5), 1)


def enrich(finding: dict) -> dict:
    """Fill cwe/owasp/cvss/references (and severity if unset) from the KB."""
    cid = finding.get("check_id")
    kb = KB.get(cid, {})
    if kb:
        finding.setdefault("cwe", kb.get("cwe", ""))
        finding.setdefault("owasp", kb.get("owasp", ""))
        finding.setdefault("references", kb.get("references", []))
        if not finding.get("cvss"):
            finding["cvss"] = kb.get("cvss", 0.0)
        # If the adapter didn't set a severity, derive it from CVSS.
        if not finding.get("severity"):
            finding["severity"] = severity_from_cvss(finding["cvss"]).value
    return finding
