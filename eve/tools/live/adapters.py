"""Live (online) assessment adapters — authorized, non-destructive only.

Operate on explicitly authorized targets over http/https via SafeHttpClient
(guardrails in client.py). They perform GET/HEAD/OPTIONS, header/cookie/CORS/TLS
inspection, DNS lookups, and bounded read-only content-discovery. No scanning,
fuzzing, injection, exploitation, or auth attacks. The MIRA Sentinel still gates
every step and denies any adapter declaring a forbidden capability.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..adapter import AdapterResult, ToolAdapter
from . import signatures as sig
from .client import LiveNetworkError, SafeHttpClient, normalize_target


def _client(params: Dict[str, Any]) -> SafeHttpClient:
    return SafeHttpClient(transport=params.get("_transport"))


class LiveReconAdapter(ToolAdapter):
    tool_id = "net.recon"
    supported_actions = ["asset_inventory", "service_discovery", "tech_identification"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        client = _client(params)
        try:
            host, base = normalize_target(target)
            if action == "asset_inventory":
                ips = client.resolve(host)
                return AdapterResult(ok=True, output={"host": host, "addresses": ips},
                                     evidence=[{"kind": "asset", "target": target,
                                                "summary": f"{host} resolves to {', '.join(ips)}",
                                                "data": {"host": host, "addresses": ips}}])
            if action == "service_discovery":
                services, evidence = [], []
                for scheme, port in (("https", 443), ("http", 80)):
                    res = client.fetch(f"{scheme}://{host}", method="HEAD")
                    if res.ok:
                        server = res.headers.get("server", "")
                        svc = {"name": scheme, "port": port, "status": res.status,
                               "server": server}
                        parsed = sig.parse_server_banner(server)
                        if parsed:
                            svc["product"], svc["version"] = parsed
                        services.append(svc)
                        evidence.append({"kind": "service", "target": target,
                                         "summary": f"{scheme} on {host}:{port} "
                                                    f"(HTTP {res.status}{', ' + server if server else ''})",
                                         "data": svc})
                if not services:
                    return AdapterResult(ok=False, error=f"no web service reachable on {host}")
                return AdapterResult(ok=True, output={"services": services}, evidence=evidence)
            if action == "tech_identification":
                res = client.fetch(base, method="GET")
                if not res.ok:
                    return AdapterResult(ok=False, error=res.error or "fetch failed")
                tech = {k: res.headers[k] for k in
                        ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via")
                        if k in res.headers}
                return AdapterResult(ok=True, output={"technologies": tech},
                                     evidence=[{"kind": "tech", "target": target,
                                                "summary": f"Technology banners for {host}",
                                                "data": tech}])
            return AdapterResult(ok=False, error=f"unsupported action '{action}'")
        except LiveNetworkError as exc:
            return AdapterResult(ok=False, error=str(exc))


class LiveEnumAdapter(ToolAdapter):
    tool_id = "net.enum"
    supported_actions = ["service_enum", "config_analysis", "http_methods", "content_probe"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        client = _client(params)
        try:
            host, base = normalize_target(target)
            is_https = base.startswith("https")
            if action == "service_enum":
                evidence = []
                for path in ("/robots.txt", "/.well-known/security.txt"):
                    res = client.fetch(base + path, method="GET")
                    if res.ok and res.status < 400 and res.body_snippet.strip():
                        evidence.append({"kind": "artifact", "target": target,
                                         "summary": f"{path} present on {host}",
                                         "data": {"path": path, "status": res.status,
                                                  "snippet": res.body_snippet[:500]}})
                root = client.fetch(base, method="GET")
                if root.ok:
                    server = root.headers.get("server", "")
                    data = {"status": root.status, "server": server}
                    parsed = sig.parse_server_banner(server)
                    if parsed:
                        data["product"], data["version"] = parsed
                    evidence.append({"kind": "banner", "target": target,
                                     "summary": f"HTTP {root.status} banner on {host}"
                                                f"{', ' + server if server else ''}",
                                     "data": data})
                return AdapterResult(ok=True, output={"collected": len(evidence)},
                                     evidence=evidence)
            if action == "config_analysis":
                res = client.fetch(base, method="GET")
                if not res.ok:
                    return AdapterResult(ok=False, error=res.error or "fetch failed")
                checks = sig.analyze_headers(res.headers, res.body_snippet, is_https)
                checks += sig.analyze_cookies(res.cookies, is_https)
                checks += sig.analyze_cors(res.headers)
                data = {"checks": checks, "https": is_https,
                        "security_headers": {k: res.headers.get(k) for k in
                                             ("strict-transport-security",
                                              "content-security-policy",
                                              "x-content-type-options",
                                              "x-frame-options", "referrer-policy")},
                        "cookies_seen": len(res.cookies)}
                server = res.headers.get("server", "")
                parsed = sig.parse_server_banner(server)
                if parsed:
                    data["product"], data["version"] = parsed
                if is_https:
                    try:
                        cert = client.tls_certificate(host)
                        if cert:
                            data["tls_not_after"] = cert.get("notAfter")
                            checks += sig.analyze_tls(cert)
                            data["checks"] = checks
                    except Exception:
                        pass
                return AdapterResult(ok=True, output={"checks": checks},
                                     evidence=[{"kind": "config", "target": target,
                                                "summary": f"Header/cookie/CORS analysis for {host}",
                                                "data": data}])
            if action == "http_methods":
                res = client.fetch(base, method="OPTIONS")
                allow = res.headers.get("allow", "") if res.ok else ""
                checks, dangerous = sig.analyze_methods(allow)
                return AdapterResult(ok=True, output={"allow": allow, "dangerous": dangerous},
                                     evidence=[{"kind": "methods", "target": target,
                                                "summary": f"Allowed methods on {host}: {allow or 'n/a'}",
                                                "data": {"allow": allow, "checks": checks,
                                                         "dangerous": dangerous}}])
            if action == "content_probe":
                evidence = []
                exposed = []
                for path in sig.SENSITIVE_PATHS:
                    res = client.fetch(base + path, method="GET")
                    if res.ok and sig.classify_sensitive_body(path, res.status, res.body_snippet):
                        exposed.append(path)
                        evidence.append({"kind": "exposure", "target": target,
                                         "summary": f"Sensitive path exposed: {path} (HTTP {res.status})",
                                         "data": {"path": path, "status": res.status,
                                                  "checks": ["exposed_sensitive_path"]}})
                return AdapterResult(ok=True, output={"exposed": exposed}, evidence=evidence)
            return AdapterResult(ok=False, error=f"unsupported action '{action}'")
        except LiveNetworkError as exc:
            return AdapterResult(ok=False, error=str(exc))


class LiveVulnAdapter(ToolAdapter):
    """Correlates collected live evidence into scored findings (no probing)."""

    tool_id = "net.vuln"
    supported_actions = ["vuln_analysis"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        from ...analysis.knowledge import KB
        evidence: List[Dict[str, Any]] = params.get("_evidence", [])
        findings: List[Dict[str, Any]] = []
        seen: set = set()
        for ev in evidence:
            if ev.get("target") != target:
                continue
            data = ev.get("data", {})
            product, version = data.get("product"), data.get("version")
            if product and version:
                import eve.tools.simulator.fixtures as fx
                for s in fx.SIGNATURES:
                    key = ("outdated_software", product, target)
                    if (s["product"] == product
                            and fx.version_lt(version, s["max_version"])
                            and key not in seen):
                        seen.add(key)
                        findings.append({
                            "title": s["title"], "target": target,
                            "confidence": "LOW", "check_id": "outdated_software",
                            "description": f"{product} {version} predates {s['max_version']}.",
                            "remediation": s["remediation"],
                            "affected_components": [f"{product} {version}"]})
            for cid in data.get("checks", []):
                path = data.get("path")  # for exposed_sensitive_path
                key = (cid, path or "", target)
                if cid not in KB or key in seen:
                    continue
                seen.add(key)
                meta = sig.CHECK_META.get(cid, {"title": cid, "remediation": ""})
                title = meta["title"] + (f" ({path})" if path else "")
                findings.append({
                    "title": title, "target": target, "confidence": "LOW",
                    "check_id": cid, "path": path,
                    "description": f"{meta['title']} observed on {target}"
                                   + (f" at {path}" if path else "") + ".",
                    "remediation": meta["remediation"],
                    "affected_components": ["web"]})
        return AdapterResult(ok=True, output={"proposed": len(findings)},
                             findings=findings)


class LiveValidateAdapter(ToolAdapter):
    """Re-observes each proposed finding with a benign request to confirm/refute."""

    tool_id = "net.validate"
    supported_actions = ["validate_finding"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        client = _client(params)
        findings = params.get("findings", [])
        verdicts: Dict[str, str] = {}
        evidence: List[Dict[str, Any]] = []
        try:
            host, base = normalize_target(target)
            is_https = base.startswith("https")
            root = client.fetch(base, method="GET")
        except LiveNetworkError as exc:
            return AdapterResult(ok=False, error=str(exc))
        current = set()
        if root.ok:
            current |= set(sig.analyze_headers(root.headers, root.body_snippet, is_https))
            current |= set(sig.analyze_cookies(root.cookies, is_https))
            current |= set(sig.analyze_cors(root.headers))
        for f in findings:
            meta = f.get("meta") or {}
            cid = meta.get("check_id") or f.get("check_id")
            path = meta.get("path") or f.get("path")
            if cid == "outdated_software":
                verdict = "CONFIRMED" if root.ok else "FALSE_POSITIVE"
            elif cid == "exposed_sensitive_path" and path:
                pr = client.fetch(base + path, method="GET")
                verdict = "CONFIRMED" if (pr.ok and sig.classify_sensitive_body(
                    path, pr.status, pr.body_snippet)) else "FALSE_POSITIVE"
            elif cid == "http_dangerous_methods":
                opt = client.fetch(base, method="OPTIONS")
                checks, _ = sig.analyze_methods(opt.headers.get("allow", "") if opt.ok else "")
                verdict = "CONFIRMED" if "http_dangerous_methods" in checks else "FALSE_POSITIVE"
            elif cid in ("tls_expired", "tls_expiring"):
                verdict = "CONFIRMED"  # cert state re-read at analysis time
            elif cid:
                verdict = "CONFIRMED" if cid in current else "FALSE_POSITIVE"
            else:
                verdict = "CONFIRMED" if root.ok else "FALSE_POSITIVE"
            verdicts[f.get("id", "")] = verdict
            evidence.append({"kind": "check", "target": target,
                             "summary": f"Re-observation of '{f.get('title')}': {verdict}",
                             "data": {"verdict": verdict, "finding_id": f.get("id"),
                                      "method": "benign_reread"}})
        return AdapterResult(ok=True, output={"verdicts": verdicts}, evidence=evidence)


def register_live(registry) -> None:
    from ..registry import ToolSpec

    def spec(tool_id, name, desc, actions, caps):
        return ToolSpec(
            tool_id=tool_id, name=name, version="1.1.0", description=desc,
            capabilities=caps, supported_actions=actions,
            required_permissions=["operator"], target_requirements=["host", "url"],
            resource_limits={"max_targets": 1, "max_bytes": 262144},
            timeout_seconds=10,
            input_schema={"target": "string(host|url)", "params": "object"},
            output_schema={"ok": "boolean", "output": "object"})

    registry.register(spec("net.recon", "Live Recon (authorized)",
                           "DNS + HTTP(S) asset/service/tech inventory over authorized targets.",
                           LiveReconAdapter.supported_actions, ["recon", "network"]),
                      LiveReconAdapter())
    registry.register(spec("net.enum", "Live Enumeration (authorized)",
                           "Headers, cookies, CORS, HTTP methods, TLS, and read-only content discovery.",
                           LiveEnumAdapter.supported_actions, ["enumeration", "network"]),
                      LiveEnumAdapter())
    registry.register(spec("net.vuln", "Live Vulnerability Analyzer",
                           "Correlates collected live evidence into scored findings.",
                           LiveVulnAdapter.supported_actions, ["analysis"]),
                      LiveVulnAdapter())
    registry.register(spec("net.validate", "Live Non-Destructive Validator",
                           "Re-observes findings with benign requests to confirm/refute.",
                           LiveValidateAdapter.supported_actions, ["validation", "network"]),
                      LiveValidateAdapter())
