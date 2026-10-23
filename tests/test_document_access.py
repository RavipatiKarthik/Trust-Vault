
import os
import re
import uuid

# Set these before importing the application.
os.environ["DATABASE_URL"] = "sqlite:///./test_trustvault.db"
os.environ["SESSION_SECRET"] = "test-only-secret-key-change-this-123456"

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.main import (
    app,
    engine,
    Document,
    Permission,
    Audit,
    Suggestion,
    User,
)


def token(client, path):
    response = client.get(path)
    assert response.status_code == 200

    match = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert match, f"CSRF token missing on {path}"

    return match.group(1)


def register_and_login(client, username, password):
    csrf = token(client, "/register")

    response = client.post(
        "/register",
        data={
            "csrf": csrf,
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303, (
        f"Registration failed for {username}. "
        f"Status: {response.status_code}. "
        f"Response body: {response.text[:2000]}"
    )

    csrf = token(client, "/login")

    response = client.post(
        "/login",
        data={
            "csrf": csrf,
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303, (
        f"Login failed for {username}. "
        f"Status: {response.status_code}. "
        f"Response body: {response.text[:2000]}"
    )

    assert response.headers["location"] == "/dashboard"


def upload_document(client, filename, content):
    csrf = token(client, "/upload")

    response = client.post(
        "/upload",
        data={"csrf": csrf},
        files={"file": (filename, content, "text/plain")},
        follow_redirects=False,
    )

    assert response.status_code == 303

    with Session(engine) as db:
        document = db.scalar(
            select(Document)
            .where(Document.filename == filename)
            .order_by(Document.id.desc())
        )

        assert document is not None
        return document.id, document.owner_id


def get_user_id(username):
    with Session(engine) as db:
        user = db.scalar(
            select(User).where(User.username == username)
        )

        assert user is not None
        return user.id


def create_suggestion(owner, document_id, target_id):
    csrf = token(owner, "/sharing")

    response = owner.post(
        "/ai/suggest",
        data={
            "csrf": csrf,
            "document_id": document_id,
            "target_id": target_id,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    with Session(engine) as db:
        suggestion = db.scalar(
            select(Suggestion)
            .where(
                Suggestion.document_id == document_id,
                Suggestion.target_id == target_id,
            )
            .order_by(Suggestion.id.desc())
        )

        assert suggestion is not None
        return suggestion.id


def test_users_cannot_download_each_others_private_documents():
    suffix = uuid.uuid4().hex[:10]
    password = "Demo-Password-82!Safe"

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, "owner" + suffix, password)

        document_id, owner_id = upload_document(
            owner, "private.txt", b"owner secret document"
        )

        register_and_login(viewer, "viewer" + suffix, password)

        response = viewer.get(
            f"/documents/{document_id}/download"
        )
        assert response.status_code == 404

        response = owner.get(
            f"/documents/{document_id}/download"
        )
        assert response.status_code == 200
        assert response.content == b"owner secret document"

        csrf = token(viewer, "/sharing")

        response = viewer.post(
            "/ai/suggest",
            data={
                "csrf": csrf,
                "document_id": document_id,
                "target_id": owner_id,
            },
            follow_redirects=False,
        )

        assert response.status_code == 403


def test_unauthenticated_download_is_redirected_to_login():
    with TestClient(app) as client:
        response = client.get(
            "/documents/1/download",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_ai_suggestion_does_not_grant_access_until_owner_approves():
    suffix = uuid.uuid4().hex[:10]
    password = "Demo-Password-82!Safe"

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, "own" + suffix, password)

        document_id, _ = upload_document(
            owner, "suggested.txt", b"restricted content"
        )

        viewer_name = "view" + suffix
        register_and_login(viewer, viewer_name, password)
        target_id = get_user_id(viewer_name)

        response = viewer.get(
            f"/documents/{document_id}/download"
        )
        assert response.status_code == 404

        suggestion_id = create_suggestion(
            owner, document_id, target_id
        )

        with Session(engine) as db:
            permission = db.scalar(
                select(Permission.id).where(
                    Permission.document_id == document_id,
                    Permission.user_id == target_id,
                )
            )
            assert permission is None

        csrf = token(owner, "/sharing")

        response = owner.post(
            f"/ai/suggestions/{suggestion_id}/approve",
            data={"csrf": csrf},
            follow_redirects=False,
        )

        assert response.status_code == 303

        response = viewer.get(
            f"/documents/{document_id}/download"
        )
        assert response.status_code == 200
        assert response.content == b"restricted content"

        with TestClient(app) as stranger:
            register_and_login(
                stranger, "str" + suffix, password
            )

            csrf = token(stranger, "/dashboard")

            response = stranger.post(
                f"/ai/suggestions/{suggestion_id}/approve",
                data={"csrf": csrf},
                follow_redirects=False,
            )

            assert response.status_code == 404


def test_suggestion_creates_audit_without_granting_access():
    suffix = uuid.uuid4().hex[:10]
    password = "Demo-Password-82!Safe"

    owner_name = "auditowner" + suffix
    viewer_name = "auditviewer" + suffix

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, owner_name, password)

        document_id, _ = upload_document(
            owner, "audit_test.txt", b"audit test content"
        )

        register_and_login(viewer, viewer_name, password)
        target_id = get_user_id(viewer_name)

        suggestion_id = create_suggestion(
            owner, document_id, target_id
        )

        with Session(engine) as db:
            permission = db.scalar(
                select(Permission.id).where(
                    Permission.document_id == document_id,
                    Permission.user_id == target_id,
                )
            )
            assert permission is None

            audit_entry = db.scalar(
                select(Audit)
                .where(
                    Audit.document_id == document_id,
                    Audit.action == "ai.permission_suggested",
                    Audit.detail.contains(
                        f"suggestion_id={suggestion_id}"
                    ),
                )
                .order_by(Audit.id.desc())
            )

            assert audit_entry is not None
            assert "no access granted" in audit_entry.detail.lower()

        response = viewer.get(
            f"/documents/{document_id}/download"
        )
        assert response.status_code == 404


def test_owner_rejection_does_not_grant_access():
    suffix = uuid.uuid4().hex[:10]
    password = "Demo-Password-82!Safe"

    owner_name = "rejectowner" + suffix
    viewer_name = "rejectviewer" + suffix

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, owner_name, password)

        document_id, _ = upload_document(
            owner, "reject_test.txt", b"rejected content"
        )

        register_and_login(viewer, viewer_name, password)
        target_id = get_user_id(viewer_name)

        suggestion_id = create_suggestion(
            owner, document_id, target_id
        )

        csrf = token(owner, "/sharing")

        response = owner.post(
            f"/ai/suggestions/{suggestion_id}/reject",
            data={"csrf": csrf},
            follow_redirects=False,
        )

        assert response.status_code == 303

        with Session(engine) as db:
            suggestion = db.get(Suggestion, suggestion_id)

            assert suggestion is not None
            assert suggestion.status == "rejected"

            permission = db.scalar(
                select(Permission.id).where(
                    Permission.document_id == document_id,
                    Permission.user_id == target_id,
                )
            )
            assert permission is None

            audit_entry = db.scalar(
                select(Audit)
                .where(
                    Audit.document_id == document_id,
                    Audit.action == "permission.rejected",
                    Audit.detail.contains(
                        f"suggestion_id={suggestion_id}"
                    ),
                )
                .order_by(Audit.id.desc())
            )

            assert audit_entry is not None

        response = viewer.get(
            f"/documents/{document_id}/download"
        )
        assert response.status_code == 404


def test_non_owner_cannot_reject_suggestion():
    suffix = uuid.uuid4().hex[:10]
    password = "Demo-Password-82!Safe"

    owner_name = "authowner" + suffix
    viewer_name = "authviewer" + suffix

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, owner_name, password)

        document_id, _ = upload_document(
            owner, "auth_reject.txt", b"authorization test"
        )

        register_and_login(viewer, viewer_name, password)
        target_id = get_user_id(viewer_name)

        suggestion_id = create_suggestion(
            owner, document_id, target_id
        )

        csrf = token(viewer, "/sharing")

        response = viewer.post(
            f"/ai/suggestions/{suggestion_id}/reject",
            data={"csrf": csrf},
            follow_redirects=False,
        )

        assert response.status_code == 404

        with Session(engine) as db:
            suggestion = db.get(Suggestion, suggestion_id)

            assert suggestion is not None
            assert suggestion.status == "pending"

            permission = db.scalar(
                select(Permission.id).where(
                    Permission.document_id == document_id,
                    Permission.user_id == target_id,
                )
            )
            assert permission is None
