
from app.main import Audit


def test_audit_record_stores_action_details():
    entry = Audit(
        actor_id=1,
        action="ai.permission_suggested",
        document_id=10,
        detail="suggestion_id=5; target_id=2; no access granted"
    )

    assert entry.actor_id == 1
    assert entry.action == "ai.permission_suggested"
    assert entry.document_id == 10
    assert "no access granted" in entry.detail


def test_audit_records_permission_approval():
    entry = Audit(
        actor_id=1,
        action="permission.approved",
        document_id=10,
        detail="suggestion_id=5; target_id=2"
    )

    assert entry.action == "permission.approved"
    assert entry.actor_id == 1
    assert entry.document_id == 10
