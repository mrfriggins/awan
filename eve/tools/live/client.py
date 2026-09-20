"""Safe live-network client for authorized, non-destructive reconnaissance.

Hard boundaries enforced here (defense in depth on top of the engine's per-target
authorization):

* Live networking is OFF unless EVE_ALLOW_LIVE is truthy.
* Only http/https, only GET/HEAD, at most a few redirects, a response-size cap,
  and a short timeout. No auth headers are ever sent.
* SSRF protection: hostnames that resolve to loopback / private / link-local /
  reserved / cloud-metadata addresses are refused unless EVE_LIVE_ALLOW_PRIVATE
  is set (for internal authorized labs).
* Optional EVE_LIVE_ALLOWED_HOSTS allowlist (comma-separated) further restricts
  which hosts may be contacted at all.

This module performs reads only. There is no scanning, fuzzing, exploitation,
or authentication attack surface here, and none may be added without also
passing the MIRA Sentinel's forbidden-capability check.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

USER_AGENT = "EVE-Recon/1.0 (+authorized-assessment)"
DEFAULT_TIMEOUT = float(os.environ.get("EVE_LIVE_TIMEOUT", "10"))
MAX_BYTES = int(os.environ.get("EVE_LIVE_MAX_BYTES", str(256 * 1024)))
MAX_REDIRECTS = 3


class LiveNetworkError(Exception):
    """A live request was refused by a guardrail or failed to complete."""


def live_enabled() -> bool:
    return os.environ.get("EVE_ALLOW_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def _allow_private() -> bool:
    return os.environ.get("EVE_LIVE_ALLOW_PRIVATE", "").strip().lower() in {"1", "true", "yes", "on"}


def _allowlist() -> Optional[set]:
    raw = os.environ.get("EVE_LIVE_ALLOWED_HOSTS", "").strip()
    if not raw:
        return None
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def normalize_target(target: str) -> tuple[str, str]:
    """Return (host, base_url) for a target identifier like 'example.com' or a URL."""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    parsed = urlparse(t)
    if parsed.scheme not in ("http", "https"):
        raise LiveNetworkError(f"scheme '{parsed.scheme}' not permitted (http/https only)")
    host = parsed.hostname
    if not host:
        raise LiveNetworkError(f"could not parse host from target '{target}'")
    base = f"{parsed.scheme}://{parsed.netloc}"
    return host, base


def _ip_is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_private or addr.is_link_local or \
            addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return True
    # Cloud metadata endpoints (explicit, in case ranges change).
    if ip in {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}:
        return True
    return False


def guard_host(host: str) -> None:
    """Raise LiveNetworkError unless this host is permitted right now."""
    if not live_enabled():
        raise LiveNetworkError(
            "live networking is disabled (set EVE_ALLOW_LIVE=true to enable)")
    allow = _allowlist()
    if allow is not None and host.lower() not in allow:
        raise LiveNetworkError(f"host '{host}' is not in EVE_LIVE_ALLOWED_HOSTS")
    if _allow_private():
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise LiveNetworkError(f"DNS resolution failed for '{host}': {exc}")
    for info in infos:
        ip = info[4][0]
        if _ip_is_blocked(ip):
            raise LiveNetworkError(
                f"host '{host}' resolves to non-public address {ip}; refused "
                f"(set EVE_LIVE_ALLOW_PRIVATE=true only for internal labs)")


@dataclass
class HttpResult:
    ok: bool
    status: int = 0
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    body_snippet: str = ""
    error: Optional[str] = None


class SafeHttpClient:
    """Minimal, guardrailed HTTP client. Optionally injectable transport (tests)."""

    def __init__(self, transport: Optional[httpx.BaseTransport] = None,
                 timeout: float = DEFAULT_TIMEOUT, max_bytes: int = MAX_BYTES) -> None:
        self._transport = transport
        self._timeout = timeout
        self._max_bytes = max_bytes

    def fetch(self, url: str, method: str = "GET") -> HttpResult:
        if method not in ("GET", "HEAD", "OPTIONS"):
            raise LiveNetworkError(
                f"method '{method}' not permitted (GET/HEAD/OPTIONS only)")
        host, _ = normalize_target(url)
        guard_host(host)
        try:
            with httpx.Client(transport=self._transport, timeout=self._timeout,
                              follow_redirects=True, max_redirects=MAX_REDIRECTS,
                              headers={"User-Agent": USER_AGENT},
                              trust_env=True) as client:
                resp = client.request(method, url if "://" in url else "https://" + url)
                body = resp.text[: self._max_bytes] if method == "GET" else ""
                cookies = resp.headers.get_list("set-cookie")
                return HttpResult(ok=True, status=resp.status_code,
                                  url=str(resp.url),
                                  headers={k.lower(): v for k, v in resp.headers.items()},
                                  cookies=list(cookies), body_snippet=body)
        except LiveNetworkError:
            raise
        except Exception as exc:  # network failure, TLS, timeout
            return HttpResult(ok=False, error=f"{type(exc).__name__}: {exc}")

    def resolve(self, host: str) -> List[str]:
        guard_host(host)
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise LiveNetworkError(f"DNS resolution failed for '{host}': {exc}")
        return sorted({info[4][0] for info in infos})

    def tls_certificate(self, host: str, port: int = 443) -> Dict[str, object]:
        """Best-effort TLS certificate metadata via a direct TLS handshake.

        May be unavailable in proxy-only egress environments; callers treat a
        failure as 'not collected', never as a finding.
        """
        guard_host(host)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=self._timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return cert or {}
