"""Result Analyzer — validate results, flag unexpected, normalize evidence/findings."""
from __future__ import annotations

from typing import List, Tuple

from ..clock import Clock, SystemClock
from ..domain.enums import Confidence, Severity
from ..domain.models import Evidence, ExecutionResult, Finding, PlannedStep
from ..evidence.manager import EvidenceManager
from ..ids import result_id
from ..tools.adapter import AdapterResult


class ResultAnalyzer:
    def __init__(self, evidence_mgr: EvidenceManager, clock: Clock | None = None) -> None:
        self.evidence = evidence_mgr
        self.clock = clock or SystemClock()

    def analyze(self, step: PlannedStep, raw: AdapterResult
                ) -> Tuple[ExecutionResult, List[Evidence], List[Finding]]:
        result = ExecutionResult(
            id=result_id(), step_id=step.id, tool_id=step.tool_id,
            action=step.action, ok=raw.ok, unexpected=raw.unexpected,
            output=raw.output, error=raw.error)

        stored_evidence: List[Evidence] = []
        for ev in raw.evidence:
            stored_evidence.append(self.evidence.record(
                step_id=step.id, target=ev.get("target", step.target),
                kind=ev.get("kind", "artifact"),
                summary=ev.get("summary", ""), data=ev.get("data", {})))

        findings: List[Finding] = []
        for f in raw.findings:
            findings.append(Finding(
                id=result_id().replace("res_", "fnd_"),
                title=f.get("title", "Finding"),
                target=f.get("target", step.target),
                phase=step.phase,
                severity=Severity(f.get("severity", "INFO")),
                confidence=Confidence(f.get("confidence", "UNVERIFIED")),
                description=f.get("description", ""),
                remediation=f.get("remediation", ""),
                affected_components=f.get("affected_components", []),
                evidence_ids=[e.id for e in stored_evidence],
                meta={"config_key": f.get("config_key"),
                      "evidence_kind": f.get("evidence_kind")}))
        return result, stored_evidence, findings
