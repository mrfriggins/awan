"""Offline simulator adapters for the five workflow phases.

All are non-destructive reads over static fixtures. They never touch a network
or shell. Each returns evidence and (for analysis phases) proposed findings with
honest confidence — never asserting an unverified issue as confirmed.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..adapter import AdapterResult, ToolAdapter
from . import fixtures as fx


class ReconAdapter(ToolAdapter):
    tool_id = "sim.recon"
    supported_actions = ["asset_inventory", "service_discovery", "tech_identification"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        host = fx.LAB.get(target)
        if host is None:
            return AdapterResult(ok=False, error=f"target '{target}' not in lab inventory")
        if action == "asset_inventory":
            return AdapterResult(ok=True, output={"host": target, "os": host["os"]},
                                 evidence=[{"kind": "asset", "target": target,
                                            "summary": f"Host {target} ({host['os']})",
                                            "data": {"os": host["os"], "kind": host["kind"]}}])
        if action == "service_discovery":
            deep = bool(params.get("deep"))
            services = list(host["services"])
            unexpected = False
            if deep and host.get("hidden_services"):
                services = services + list(host["hidden_services"])
                unexpected = True
            ev = [{"kind": "service", "target": target,
                   "summary": f"{s['name']} on {target}:{s['port']} "
                              f"({s['product']} {s['version']})",
                   "data": s} for s in services]
            return AdapterResult(ok=True, output={"services": services},
                                 evidence=ev, unexpected=unexpected)
        if action == "tech_identification":
            techs = [{"product": s["product"], "version": s["version"]}
                     for s in host["services"]]
            return AdapterResult(ok=True, output={"technologies": techs},
                                 evidence=[{"kind": "tech", "target": target,
                                            "summary": f"Technologies on {target}",
                                            "data": {"technologies": techs}}])
        return AdapterResult(ok=False, error=f"unsupported action '{action}'")


class EnumAdapter(ToolAdapter):
    tool_id = "sim.enum"
    supported_actions = ["service_enum", "config_analysis"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        host = fx.LAB.get(target)
        if host is None:
            return AdapterResult(ok=False, error=f"target '{target}' not in lab inventory")
        if action == "service_enum":
            svc = params.get("service")
            matches = [s for s in host["services"] if s["name"] == svc] if svc else host["services"]
            ev = [{"kind": "banner", "target": target,
                   "summary": f"Banner {s['product']} {s['version']} on {target}:{s['port']}",
                   "data": s} for s in matches]
            return AdapterResult(ok=True, output={"services": matches}, evidence=ev)
        if action == "config_analysis":
            svc = params.get("service", "http")
            cfg = host.get("configs", {}).get(svc, {})
            issues = {k: v for k, v in cfg.items() if k in fx.CONFIG_ISSUES and v}
            ev = [{"kind": "config", "target": target,
                   "summary": f"Config for {svc} on {target}",
                   "data": {"service": svc, "config": cfg, "flagged": list(issues)}}]
            return AdapterResult(ok=True, output={"service": svc, "flagged": list(issues)},
                                 evidence=ev)
        return AdapterResult(ok=False, error=f"unsupported action '{action}'")


class VulnAdapter(ToolAdapter):
    """Analyzes evidence (passed in params['_evidence']) into proposed findings."""

    tool_id = "sim.vuln"
    supported_actions = ["vuln_analysis"]

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        evidence: List[Dict[str, Any]] = params.get("_evidence", [])
        findings: List[Dict[str, Any]] = []
        seen: set = set()
        for ev in evidence:
            if ev.get("target") != target:
                continue
            data = ev.get("data", {})
            product = data.get("product")
            version = data.get("version")
            if product and version:
                for sig in fx.SIGNATURES:
                    key = (sig["title"], target)
                    if (sig["product"] == product
                            and fx.version_lt(version, sig["max_version"])
                            and key not in seen):
                        seen.add(key)
                        findings.append({
                            "title": sig["title"], "target": target,
                            "severity": sig["severity"], "confidence": "LOW",
                            "description": f"{product} {version} predates "
                                           f"{sig['max_version']} ({sig['cwe']}).",
                            "remediation": sig["remediation"],
                            "affected_components": [f"{product} {version}"],
                            "check_id": "outdated_software",
                            "evidence_kind": ev.get("kind")})
            for flagged in data.get("flagged", []):
                issue = fx.CONFIG_ISSUES.get(flagged)
                ckey = (issue["title"], target) if issue else None
                if issue and ckey not in seen:
                    seen.add(ckey)
                    findings.append({
                        "title": issue["title"], "target": target,
                        "severity": issue["severity"], "confidence": "LOW",
                        "description": f"Configuration flag '{flagged}' on {target} "
                                       f"({issue['cwe']}).",
                        "remediation": issue["remediation"],
                        "affected_components": [data.get("service", "web")],
                        "config_key": flagged,
                        "check_id": {"directory_listing": "directory_listing",
                                     "server_tokens": "server_version_disclosure"}.get(flagged)})
        return AdapterResult(ok=True, output={"proposed": len(findings)},
                             findings=findings)


class ValidateAdapter(ToolAdapter):
    """Non-destructive validation of a proposed finding."""

    tool_id = "sim.validate"
    supported_actions = ["validate_finding"]

    @staticmethod
    def _verdict_for(finding: Dict[str, Any]) -> str:
        meta = finding.get("meta") or {}
        config_key = meta.get("config_key") or finding.get("config_key")
        if config_key:
            issue = fx.CONFIG_ISSUES.get(config_key, {})
            return "CONFIRMED" if issue.get("validatable") else "FALSE_POSITIVE"
        return "CONFIRMED"

    def execute(self, action: str, target: str, params: Dict[str, Any]) -> AdapterResult:
        if "findings" in params:
            verdicts: Dict[str, str] = {}
            evidence: List[Dict[str, Any]] = []
            for f in params["findings"]:
                v = self._verdict_for(f)
                verdicts[f.get("id", "")] = v
                evidence.append({"kind": "check", "target": target,
                                 "summary": f"Non-destructive validation of "
                                            f"'{f.get('title')}': {v}",
                                 "data": {"verdict": v, "finding_id": f.get("id"),
                                          "method": "benign_read"}})
            return AdapterResult(ok=True, output={"verdicts": verdicts},
                                 evidence=evidence)
        finding = params.get("finding", {})
        config_key = (finding.get("meta") or {}).get("config_key") or finding.get("config_key")
        verdict = self._verdict_for(finding)
        if config_key:
            return AdapterResult(ok=True, output={"verdict": verdict},
                                 evidence=[{"kind": "check", "target": target,
                                            "summary": f"Non-destructive validation of "
                                                       f"'{finding.get('title')}': {verdict}",
                                            "data": {"verdict": verdict,
                                                     "method": "benign_read"}}])
        return AdapterResult(ok=True, output={"verdict": "CONFIRMED"},
                             evidence=[{"kind": "check", "target": target,
                                        "summary": f"Banner re-read confirms "
                                                   f"'{finding.get('title')}'",
                                        "data": {"verdict": "CONFIRMED",
                                                 "method": "banner_reread"}}])


def register_simulator(registry) -> None:
    from ..registry import ToolSpec

    def spec(tool_id, name, desc, actions, caps, treq):
        return ToolSpec(
            tool_id=tool_id, name=name, version="1.0.0", description=desc,
            capabilities=caps, supported_actions=actions,
            required_permissions=["operator"], target_requirements=treq,
            resource_limits={"max_targets": 1}, timeout_seconds=15,
            input_schema={"target": "string", "params": "object"},
            output_schema={"ok": "boolean", "output": "object"})

    registry.register(spec("sim.recon", "Offline Recon Simulator",
                           "Asset/service/tech inventory over lab fixtures.",
                           ReconAdapter.supported_actions, ["recon"], ["host"]),
                      ReconAdapter())
    registry.register(spec("sim.enum", "Offline Enumeration Simulator",
                           "Service and configuration enumeration.",
                           EnumAdapter.supported_actions, ["enumeration"], ["host"]),
                      EnumAdapter())
    registry.register(spec("sim.vuln", "Offline Vulnerability Analyzer",
                           "Correlates evidence into proposed findings.",
                           VulnAdapter.supported_actions, ["analysis"], ["host"]),
                      VulnAdapter())
    registry.register(spec("sim.validate", "Offline Non-Destructive Validator",
                           "Confirms or refutes findings without destructive checks.",
                           ValidateAdapter.supported_actions, ["validation"], ["host"]),
                      ValidateAdapter())
