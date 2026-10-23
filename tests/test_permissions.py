
from app.main import can_read, User, Document, Permission


def test_owner_can_read_own_document():
    owner = User(id=1, username="owner", role="owner")
    document = Document(id=10, owner_id=1, filename="test.pdf",
                         stored_name="test.pdf")

    assert can_read(None, owner, document) is True


def test_unshared_user_cannot_read_document():
    class FakeDB:
        def scalar(self, query):
            return None

    owner = User(id=1, username="owner", role="owner")
    viewer = User(id=2, username="viewer", role="viewer")
    document = Document(id=10, owner_id=1, filename="test.pdf",
                        stored_name="test.pdf")

    assert can_read(FakeDB(), viewer, document) is False


def test_admin_role_does_not_grant_private_document_access():
    class FakeDB:
        def scalar(self, query):
            return None

    admin = User(id=3, username="admin", role="admin")
    document = Document(id=10, owner_id=1, filename="test.pdf",
                        stored_name="test.pdf")

    assert can_read(FakeDB(), admin, document) is False
