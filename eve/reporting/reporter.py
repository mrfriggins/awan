"""Reporting Engine — executive + technical assessment reports."""
from __future__ import annotations

from collections import Counter
from typing import List

from ..clock import Clock, SystemClock
from ..domain.enums import Confidence, Severity, StepState
from ..domain.models import Finding, Plan, Report

_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
              Severity.LOW: 3, Severity.INFO: 4}


class ReportingEngine:
    def __init__(self, clock: Clock | None = None) -> None:
        self.clock = clock or SystemClock()

    def build(self, *, operation_id: str, goal: str, targets: List[str],
              plan: Plan, findings: List[Finding], adaptations: int,
              outcome: str) -> Report:
        succeeded = sum(1 for s in plan.steps if s.state == StepState.SUCCEEDED)
        failed = sum(1 for s in plan.steps if s.state == StepState.FAILED)
        confirmed = [f for f in findings if f.confidence == Confidence.CONFIRMED]
        fps = [f for f in findings if f.confidence == Confidence.FALSE_POSITIVE]
        reportable = [f for f in findings if f.confidence != Confidence.FALSE_POSITIVE]
        reportable.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), -f.risk_score))

        breakdown = Counter(f.severity.value for f in reportable)
        risk = round(max([f.risk_score for f in reportable], default=0.0), 1)
        owasp = sorted({f.owasp for f in reportable if f.owasp})
        methodology = sorted({f"{s.phase.value}:{s.tool_id}.{s.action}"
                              for s in plan.steps if s.state == StepState.SUCCEEDED})

        top = reportable[0] if reportable else None
        exec_summary = (
            f"Assessment of {', '.join(targets)} executed {succeeded}/{len(plan.steps)} "
            f"steps across {len({s.phase for s in plan.steps})} phase(s). "
            f"{len(confirmed)} confirmed and {len(reportable) - len(confirmed)} "
            f"potential finding(s); {len(fps)} false positive(s) discarded. "
            + (f"Highest risk: {top.title} ({top.severity.value}, risk {top.risk_score}/10). "
               if top else "No issues identified. ")
            + f"Aggregate risk score {risk}/10.")

        summary = (
            f"Assessed {len(targets)} target(s) across {len(plan.steps)} steps. "
            f"{len(confirmed)} confirmed, "
            f"{len(reportable) - len(confirmed)} unconfirmed, {len(fps)} false positive(s). "
            f"Outcome: {outcome}.")

        return Report(
            operation_id=operation_id, goal=goal, generated_at=self.clock.now(),
            summary=summary, targets=targets, findings=reportable,
            steps_total=len(plan.steps), steps_succeeded=succeeded,
            steps_failed=failed, adaptations=adaptations, outcome=outcome,
            executive_summary=exec_summary, severity_breakdown=dict(breakdown),
            risk_score=risk, owasp_coverage=owasp, methodology=methodology)


def render_markdown(report: Report) -> str:
    """Render a professional Markdown assessment report."""
    lines: List[str] = []
    lines.append(f"# Security Assessment Report")
    lines.append("")
    lines.append(f"- **Operation:** `{report.operation_id}`")
    lines.append(f"- **Objective:** {report.goal}")
    lines.append(f"- **Targets:** {', '.join(report.targets)}")
    lines.append(f"- **Generated:** {report.generated_at.isoformat()}")
    lines.append(f"- **Outcome:** {report.outcome}")
    lines.append(f"- **Aggregate risk:** {report.risk_score}/10")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append(report.executive_summary)
    lines.append("")
    lines.append("## Severity breakdown")
    lines.append("")
    if report.severity_breakdown:
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in report.severity_breakdown:
                lines.append(f"| {sev} | {report.severity_breakdown[sev]} |")
    else:
        lines.append("_No reportable findings._")
    lines.append("")
    if report.owasp_coverage:
        lines.append("## OWASP Top-10 categories observed")
        lines.append("")
        for o in report.owasp_coverage:
            lines.append(f"- {o}")
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("_No findings._")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"### {i}. {f.title}")
        lines.append("")
        lines.append(f"- **Target:** {f.target}")
        lines.append(f"- **Severity:** {f.severity.value}  |  **Confidence:** "
                     f"{f.confidence.value}  |  **Risk:** {f.risk_score}/10  |  "
                     f"**CVSS:** {f.cvss}")
        if f.cwe or f.owasp:
            lines.append(f"- **{f.cwe}**  |  {f.owasp}")
        if f.affected_components:
            lines.append(f"- **Affected:** {', '.join(f.affected_components)}")
        lines.append("")
        if f.description:
            lines.append(f.description)
            lines.append("")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
        if f.references:
            lines.append("**References:** " + ", ".join(f.references))
            lines.append("")
    lines.append("## Methodology (executed steps)")
    lines.append("")
    for m in report.methodology:
        lines.append(f"- {m}")
    lines.append("")
    lines.append("---")
    lines.append("_Generated by the EVE Offensive Execution Engine — authorized, "
                 "non-destructive assessment._")
    return "\n".join(lines)
