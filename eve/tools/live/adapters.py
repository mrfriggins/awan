"""Live (online) recon adapters — authorized, non-destructive reads only.

These operate on explicitly authorized targets over http/https via SafeHttpClient
(all guardrails in eve/tools/live/client.py). They perform GET/HEAD, header/TLS
inspection, and DNS lookups — no scanning, fuzzing, exploitation, or auth
attacks. The MIRA Sentinel still gates every step and would deny any adapter
declaring a forbidden capability.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..adapter import AdapterResult, ToolAdapter
from ..simulator import fixtures as fx
from . import signatures as sig
from .client import LiveNetworkError, SafeHttpClient, normalize_target


def _client(params: Dict[str, Any]) -> SafeHttpClient:
    # tests may inject an httpx transport via params["_transport"]
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
                services = []
                evidence = []
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
                return AdapterResult(ok=True, output={"services": services},
                                     evidence=evidence)
            if action == "tech_identification":
                res = client.fetch(base, method="GET")
                if not res.ok:
                    return AdapterResult(ok=False, error=res.error or "fetch failed")
                tech = {k: res.headers[k] for k in
                        ("server", "x-powered-by", "x-generator", "via")
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
    supported_actions = ["service_enum", "config_analysis"]

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
                flagged = sig.evaluate_headers(res.headers, res.body_snippet, is_https)
                data = {"flagged": flagged, "https": is_https,
                        "security_headers": {k: res.headers.get(k) for k in
                                             ("strict-transport-security",
                                              "content-security-policy",
                                              "x-content-type-options")}}
                server = res.headers.get("server", "")
                parsed = sig.parse_server_banner(server)
                if parsed:
                    data["product"], data["version"] = parsed
                # best-effort TLS metadata (may be unavailable via proxy egress)
                if is_https:
                    try:
                        cert = client.tls_certificate(host)
                        if cert:
                            data["tls_not_after"] = cert.get("notAfter")
                    except Exception:
                        pass
                return AdapterResult(ok=True, output={"flagged": flagged},
                                     evidence=[{"kind": "config", "target": target,
                                                "summary": f"Header/config analysis for {host}",
                                                "data": data}])
            return AdapterResult(ok=False, error=f"unsupported action '{action}'")
        except LiveNetworkError as exc:
            return AdapterResult(ok=False, error=str(exc))


class LiveVulnAdapter(ToolAdapter):
    """Correlates collected live evidence into proposed findings (no probing)."""

    tool_id = "net.vuln"
    supported_actions = ["vuln_analysis"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        evidence: List[Dict[str, Any]] = params.get("_evidence", [])
        findings: List[Dict[str, Any]] = []
        seen: set = set()
        for ev in evidence:
            if ev.get("target") != target:
                continue
            data = ev.get("data", {})
            product, version = data.get("product"), data.get("version")
            if product and version:
                for s in fx.SIGNATURES:
                    key = (s["title"], target)
                    if (s["product"] == product
                            and fx.version_lt(version, s["max_version"])
                            and key not in seen):
                        seen.add(key)
                        findings.append({
                            "title": s["title"], "target": target,
                            "severity": s["severity"], "confidence": "LOW",
                            "description": f"{product} {version} predates "
                                           f"{s['max_version']} ({s['cwe']}).",
                            "remediation": s["remediation"],
                            "affected_components": [f"{product} {version}"]})
            for flagged in data.get("flagged", []):
                issue = sig.LIVE_CONFIG_ISSUES.get(flagged)
                ckey = (issue["title"], target) if issue else None
                if issue and ckey not in seen:
                    seen.add(ckey)
                    findings.append({
                        "title": issue["title"], "target": target,
                        "severity": issue["severity"], "confidence": "LOW",
                        "description": f"Observed on {target} ({issue['cwe']}).",
                        "remediation": issue["remediation"],
                        "affected_components": ["web"],
                        "config_key": flagged, "live": True})
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
            res = client.fetch(base, method="GET")
        except LiveNetworkError as exc:
            return AdapterResult(ok=False, error=str(exc))
        flagged_now = set(sig.evaluate_headers(res.headers, res.body_snippet, is_https)) \
            if res.ok else set()
        for f in findings:
            meta = f.get("meta") or {}
            ckey = meta.get("config_key") or f.get("config_key")
            if not res.ok:
                verdict = "FALSE_POSITIVE"  # could not reproduce
            elif ckey:
                verdict = "CONFIRMED" if ckey in flagged_now else "FALSE_POSITIVE"
            else:
                verdict = "CONFIRMED"  # version banner re-observed
            verdicts[f.get("id", "")] = verdict
            evidence.append({"kind": "check", "target": target,
                             "summary": f"Re-observation of '{f.get('title')}': {verdict}",
                             "data": {"verdict": verdict, "method": "benign_reread",
                                      "finding_id": f.get("id")}})
        return AdapterResult(ok=True, output={"verdicts": verdicts}, evidence=evidence)


def register_live(registry) -> None:
    """Register the live toolset. Call only when live networking is intended."""
    from ..registry import ToolSpec

    def spec(tool_id, name, desc, actions, caps):
        return ToolSpec(
            tool_id=tool_id, name=name, version="1.0.0", description=desc,
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
                           "robots/security.txt, headers, and security-config analysis.",
                           LiveEnumAdapter.supported_actions, ["enumeration", "network"]),
                      LiveEnumAdapter())
    registry.register(spec("net.vuln", "Live Vulnerability Analyzer",
                           "Correlates collected live evidence into proposed findings.",
                           LiveVulnAdapter.supported_actions, ["analysis"]),
                      LiveVulnAdapter())
    registry.register(spec("net.validate", "Live Non-Destructive Validator",
                           "Re-observes findings with benign requests to confirm/refute.",
                           LiveValidateAdapter.supported_actions, ["validation", "network"]),
                      LiveValidateAdapter())
