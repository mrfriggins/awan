"""State persistence, restart survival, audit integrity."""
from eve.config import Settings, ExecutionLimits
from eve.domain.enums import OperationState
from eve.factory import build_engine


def test_operation_persists_and_reloads(authorized_engine, settings, clock):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED

    # Simulate an application restart: brand-new engine on the same database.
    engine2 = build_engine(settings, clock=clock)
    reloaded = engine2.repo.load_operation(snap.id)
    assert reloaded is not None
    assert reloaded.state == OperationState.SUCCEEDED
    assert reloaded.report is not None
    assert len(reloaded.findings) == len(snap.findings)


def test_stopped_operation_not_auto_restarted(authorized_engine, settings, clock):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.step(snap.id)
    c.emergency_stop_all("halt")
    assert c.get_snapshot(snap.id).state == OperationState.STOPPED
    engine2 = build_engine(settings, clock=clock)
    reloaded = engine2.repo.load_operation(snap.id)
    assert reloaded.state == OperationState.STOPPED  # stays stopped


def test_audit_chain_intact(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.run_to_completion(snap.id)
    ok, msg = c.audit.verify_chain(snap.id)
    assert ok is True, msg


def test_audit_chain_detects_tampering(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.run_to_completion(snap.id)
    # Tamper with a persisted event.
    from eve.persistence.tables import OperationEventRow
    with authorized_engine.db.session() as s:
        row = s.query(OperationEventRow).filter_by(operation_id=snap.id, seq=3).one()
        row.message = "TAMPERED"
    ok, msg = c.audit.verify_chain(snap.id)
    assert ok is False


def test_events_and_results_persisted(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full", targets=["lab-web-01"])
    c.run_to_completion(snap.id)
    events = authorized_engine.repo.list_events(snap.id)
    evidence = authorized_engine.repo.list_evidence(snap.id)
    assert len(events) > 10
    assert len(evidence) >= 4
