"""Offline lab fixtures. Entirely static, non-destructive test data."""
from __future__ import annotations

from typing import Any, Dict

LAB: Dict[str, Dict[str, Any]] = {
    "lab-web-01": {
        "kind": "host",
        "os": "Ubuntu 20.04 (lab image)",
        "services": [
            {"port": 22, "proto": "tcp", "name": "ssh", "product": "OpenSSH",
             "version": "8.2p1"},
            {"port": 80, "proto": "tcp", "name": "http", "product": "nginx",
             "version": "1.18.0"},
        ],
        "hidden_services": [
            {"port": 8080, "proto": "tcp", "name": "http-admin", "product": "nginx",
             "version": "1.18.0", "note": "staging admin panel"},
        ],
        "configs": {
            "http": {"directory_listing": True, "server_tokens": "on", "tls": False},
        },
    },
    "lab-db-01": {
        "kind": "host",
        "os": "Debian 11 (lab image)",
        "services": [
            {"port": 22, "proto": "tcp", "name": "ssh", "product": "OpenSSH",
             "version": "8.4p1"},
            {"port": 5432, "proto": "tcp", "name": "postgresql", "product": "PostgreSQL",
             "version": "12.2"},
        ],
        "hidden_services": [],
        "configs": {
            "postgresql": {"trust_auth_local": False, "tls": True},
        },
    },
}

SIGNATURES = [
    {"product": "nginx", "max_version": "1.20.0",
     "title": "Outdated nginx web server", "severity": "MEDIUM",
     "cwe": "CWE-1104", "remediation": "Upgrade nginx to a supported release."},
    {"product": "PostgreSQL", "max_version": "13.0",
     "title": "Outdated PostgreSQL server", "severity": "LOW",
     "cwe": "CWE-1104", "remediation": "Upgrade PostgreSQL to a supported major."},
]

CONFIG_ISSUES = {
    "directory_listing": {
        "title": "HTTP directory listing enabled", "severity": "MEDIUM",
        "cwe": "CWE-548",
        "remediation": "Disable autoindex/directory listing on the web server.",
        "validatable": True,
    },
    "server_tokens": {
        "title": "Web server version disclosure", "severity": "LOW",
        "cwe": "CWE-200",
        "remediation": "Set server_tokens off to suppress version banners.",
        "validatable": False,
    },
}


def version_lt(a: str, b: str) -> bool:
    def norm(v: str):
        out = []
        for part in v.replace("p", ".").split("."):
            digits = "".join(ch for ch in part if ch.isdigit())
            out.append(int(digits) if digits else 0)
        return out
    return norm(a) < norm(b)
