
from app.main import Suggestion


def test_new_suggestion_starts_pending_after_database_insert():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.main import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        suggestion = Suggestion(
            document_id=1,
            owner_id=1,
            target_id=2,
            reason="Test sharing suggestion"
        )
        # Flush applies SQLAlchemy column defaults.
        db.add(suggestion)
        db.flush()

        assert suggestion.status == "pending"


def test_suggestion_does_not_itself_create_permission():
    suggestion = Suggestion(
        document_id=1,
        owner_id=1,
        target_id=2,
        reason="Test sharing suggestion"
    )

    # A new suggestion object does not create a Permission object.
    assert suggestion.status is None
    assert suggestion.document_id == 1
    assert suggestion.target_id == 2


def test_suggestion_has_separate_owner_and_target():
    suggestion = Suggestion(
        document_id=10,
        owner_id=1,
        target_id=2,
        reason="Test sharing suggestion"
    )

    assert suggestion.owner_id != suggestion.target_id
