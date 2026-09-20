"""Non-destructive live-recon rulebook.

All rules are observations over data EVE already retrieved with a benign GET/HEAD
(headers, TLS metadata, a small body snippet). Nothing here probes, fuzzes, or
exploits. Version-based rules reuse the shared simulator signature list.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..simulator import fixtures as fx  # reuse product/version signatures

# Security-header / config observations. `validatable=True` means EVE can re-run
# the same benign check during the VALIDATION phase to confirm reproducibility.
LIVE_CONFIG_ISSUES: Dict[str, dict] = {
    "missing_hsts": {
        "title": "Missing HTTP Strict-Transport-Security header",
        "severity": "MEDIUM", "cwe": "CWE-319", "validatable": True,
        "remediation": "Send Strict-Transport-Security with a max-age of at least 15552000."},
    "missing_csp": {
        "title": "Missing Content-Security-Policy header",
        "severity": "LOW", "cwe": "CWE-1021", "validatable": True,
        "remediation": "Define a Content-Security-Policy to constrain resource loading."},
    "missing_xcto": {
        "title": "Missing X-Content-Type-Options: nosniff",
        "severity": "LOW", "cwe": "CWE-16", "validatable": True,
        "remediation": "Set X-Content-Type-Options: nosniff."},
    "server_version_disclosure": {
        "title": "Server version disclosed in banner",
        "severity": "LOW", "cwe": "CWE-200", "validatable": True,
        "remediation": "Suppress version tokens in the Server header."},
    "directory_listing": {
        "title": "HTTP directory listing enabled",
        "severity": "MEDIUM", "cwe": "CWE-548", "validatable": True,
        "remediation": "Disable automatic directory indexing."},
}

_SERVER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_\-]*)/(\d[\d.]*\w*)")


def parse_server_banner(server: str) -> Optional[Tuple[str, str]]:
    """'nginx/1.18.0 (Ubuntu)' -> ('nginx', '1.18.0'). Returns None if no version."""
    if not server:
        return None
    m = _SERVER_RE.match(server.strip())
    if not m:
        return None
    product = {"nginx": "nginx", "apache": "Apache", "openssh": "OpenSSH"}.get(
        m.group(1).lower(), m.group(1))
    return product, m.group(2)


def evaluate_headers(headers: Dict[str, str], body_snippet: str,
                     is_https: bool) -> List[str]:
    """Return the LIVE_CONFIG_ISSUES keys observed for this response."""
    flagged: List[str] = []
    if is_https and "strict-transport-security" not in headers:
        flagged.append("missing_hsts")
    if "content-security-policy" not in headers:
        flagged.append("missing_csp")
    if "x-content-type-options" not in headers:
        flagged.append("missing_xcto")
    server = headers.get("server", "")
    if parse_server_banner(server) is not None:
        flagged.append("server_version_disclosure")
    if body_snippet and re.search(r"<title>\s*Index of /", body_snippet, re.IGNORECASE):
        flagged.append("directory_listing")
    return flagged
