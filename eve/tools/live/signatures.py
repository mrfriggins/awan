"""Non-destructive live-assessment check suite.

Every function here is a passive observation over data EVE already retrieved with
a benign request (headers, Set-Cookie, a small body snippet, TLS metadata, DNS
records). Nothing probes with payloads, fuzzes, or exploits. Titles/remediation
live here; CWE/OWASP/CVSS/severity are supplied by eve/analysis/knowledge.py.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Dict, List, Optional, Tuple

from ..simulator import fixtures as fx  # shared product/version signatures

# Human-facing text per check. Scoring/mappings come from the knowledge base.
CHECK_META: Dict[str, dict] = {
    "missing_hsts": {"title": "Missing HTTP Strict-Transport-Security header",
                     "remediation": "Send Strict-Transport-Security with max-age >= 15552000."},
    "missing_csp": {"title": "Missing Content-Security-Policy header",
                    "remediation": "Define a Content-Security-Policy to constrain resource loading."},
    "missing_xcto": {"title": "Missing X-Content-Type-Options: nosniff",
                     "remediation": "Set X-Content-Type-Options: nosniff."},
    "missing_xfo": {"title": "Missing X-Frame-Options / frame-ancestors",
                    "remediation": "Set X-Frame-Options: DENY or a CSP frame-ancestors directive."},
    "missing_referrer_policy": {"title": "Missing Referrer-Policy header",
                                "remediation": "Set a restrictive Referrer-Policy (e.g. no-referrer-when-downgrade)."},
    "missing_permissions_policy": {"title": "Missing Permissions-Policy header",
                                   "remediation": "Set a Permissions-Policy to disable unused browser features."},
    "clickjacking": {"title": "Page is framable (clickjacking exposure)",
                     "remediation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."},
    "cookie_insecure": {"title": "Session cookie missing Secure attribute",
                        "remediation": "Set the Secure attribute on cookies over HTTPS."},
    "cookie_no_httponly": {"title": "Session cookie missing HttpOnly attribute",
                           "remediation": "Set HttpOnly on session cookies."},
    "cookie_no_samesite": {"title": "Session cookie missing SameSite attribute",
                           "remediation": "Set SameSite=Lax or Strict on session cookies."},
    "cors_wildcard_credentials": {"title": "CORS allows any origin with credentials",
                                  "remediation": "Never combine Access-Control-Allow-Origin: * with credentials."},
    "cors_wildcard": {"title": "CORS allows any origin",
                      "remediation": "Restrict Access-Control-Allow-Origin to trusted origins."},
    "http_dangerous_methods": {"title": "Dangerous HTTP methods enabled",
                               "remediation": "Disable PUT/DELETE/TRACE/CONNECT unless required."},
    "server_version_disclosure": {"title": "Server version disclosed in banner",
                                  "remediation": "Suppress version tokens in the Server header."},
    "directory_listing": {"title": "HTTP directory listing enabled",
                          "remediation": "Disable automatic directory indexing."},
    "exposed_sensitive_path": {"title": "Sensitive path exposed",
                               "remediation": "Restrict access to the exposed path and remove it from web roots."},
    "tls_expired": {"title": "TLS certificate expired",
                    "remediation": "Renew the certificate immediately."},
    "tls_expiring": {"title": "TLS certificate expiring soon",
                     "remediation": "Renew the certificate before expiry."},
    "missing_dmarc": {"title": "Missing DMARC policy",
                      "remediation": "Publish a DMARC TXT record with a reject/quarantine policy."},
    "missing_spf": {"title": "Missing SPF record",
                    "remediation": "Publish an SPF TXT record authorizing sending hosts."},
    "outdated_software": {"title": "Outdated software component",
                          "remediation": "Upgrade to a supported release."},
}

# Bounded, read-only content-discovery list (existence checks only).
SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/.svn/entries", "/server-status",
    "/actuator/health", "/.well-known/security.txt", "/sitemap.xml",
    "/backup.zip", "/config.php.bak", "/phpinfo.php",
]
_SENSITIVE_SIGNATURE = re.compile(
    r"\[core\]|DB_PASSWORD|APP_KEY|Apache Status|<\?php|BEGIN RSA|aws_secret",
    re.IGNORECASE)

_SERVER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_\-]*)/(\d[\d.]*\w*)")
_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def parse_server_banner(server: str) -> Optional[Tuple[str, str]]:
    if not server:
        return None
    m = _SERVER_RE.match(server.strip())
    if not m:
        return None
    product = {"nginx": "nginx", "apache": "Apache", "openssh": "OpenSSH"}.get(
        m.group(1).lower(), m.group(1))
    return product, m.group(2)


def analyze_headers(headers: Dict[str, str], body_snippet: str,
                    is_https: bool) -> List[str]:
    checks: List[str] = []
    if is_https and "strict-transport-security" not in headers:
        checks.append("missing_hsts")
    csp = headers.get("content-security-policy", "")
    if not csp:
        checks.append("missing_csp")
    if "x-content-type-options" not in headers:
        checks.append("missing_xcto")
    xfo = "x-frame-options" in headers
    frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not frame_ancestors:
        checks.append("missing_xfo")
        checks.append("clickjacking")
    if "referrer-policy" not in headers:
        checks.append("missing_referrer_policy")
    if "permissions-policy" not in headers:
        checks.append("missing_permissions_policy")
    if parse_server_banner(headers.get("server", "")) is not None:
        checks.append("server_version_disclosure")
    if body_snippet and re.search(r"<title>\s*Index of /", body_snippet, re.IGNORECASE):
        checks.append("directory_listing")
    return checks


def analyze_cookies(set_cookie_values: List[str], is_https: bool) -> List[str]:
    checks: List[str] = []
    for raw in set_cookie_values:
        low = raw.lower()
        if is_https and "secure" not in low:
            checks.append("cookie_insecure")
        if "httponly" not in low:
            checks.append("cookie_no_httponly")
        if "samesite" not in low:
            checks.append("cookie_no_samesite")
    return list(dict.fromkeys(checks))  # dedupe, keep order


def analyze_cors(headers: Dict[str, str]) -> List[str]:
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        return ["cors_wildcard_credentials"] if acac == "true" else ["cors_wildcard"]
    return []


def analyze_methods(allow_header: str) -> Tuple[List[str], List[str]]:
    methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    dangerous = sorted(set(methods) & _DANGEROUS_METHODS)
    return (["http_dangerous_methods"] if dangerous else []), dangerous


def analyze_tls(cert: dict, now: Optional[_dt.datetime] = None) -> List[str]:
    if not cert or "notAfter" not in cert:
        return []
    now = now or _dt.datetime.now(_dt.timezone.utc)
    try:
        exp = _dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=_dt.timezone.utc)
    except (ValueError, KeyError):
        return []
    if exp <= now:
        return ["tls_expired"]
    if exp <= now + _dt.timedelta(days=21):
        return ["tls_expiring"]
    return []


def classify_sensitive_body(path: str, status: int, body: str) -> bool:
    """Conservative: only flag a 200 whose body matches a sensitive-content
    signature (config keys, secrets, source, status pages). This avoids the
    common false positive of servers returning a 200 soft-404 HTML page."""
    if status != 200 or not body:
        return False
    return bool(_SENSITIVE_SIGNATURE.search(body))
