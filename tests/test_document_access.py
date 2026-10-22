
import os
import re
import uuid

# Set these before importing the application.
os.environ["DATABASE_URL"] = "sqlite:///./test_trustvault.db"
os.environ["SESSION_SECRET"] = "test-only-secret-key-change-this-123456"

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.main import app, engine, Document, Permission


def token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert match, f"CSRF token missing on {path}"
    return match.group(1)


def register_and_login(client, username, password):
    csrf = token(client, "/register")
    response = client.post("/register", data={
        "csrf": csrf, "username": username, "password": password
    }, follow_redirects=False)
    assert response.status_code == 303

    csrf = token(client, "/login")
    response = client.post("/login", data={
        "csrf": csrf, "username": username, "password": password
    }, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_users_cannot_download_each_others_private_documents():
    suffix = uuid.uuid4().hex[:10]
    owner_name = "owner" + suffix
    viewer_name = "viewer" + suffix
    password = "Demo-Password-82!Safe"

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, owner_name, password)
        csrf = token(owner, "/upload")
        response = owner.post(
            "/upload",
            data={"csrf": csrf},
            files={"file": ("private.txt", b"owner secret document", "text/plain")},
            follow_redirects=False,
        )
        assert response.status_code == 303

        with Session(engine) as db:
            doc = db.scalar(select(Document).where(
                Document.filename == "private.txt"
            ).order_by(Document.id.desc()))
            assert doc is not None
            document_id = doc.id
            owner_id = doc.owner_id

        register_and_login(viewer, viewer_name, password)

        # A guessed document ID must not disclose the private file.
        response = viewer.get(f"/documents/{document_id}/download")
        assert response.status_code == 404

        # The actual owner can download it.
        response = owner.get(f"/documents/{document_id}/download")
        assert response.status_code == 200
        assert response.content == b"owner secret document"

        # A viewer cannot create a permission suggestion for someone else's file.
        csrf = token(viewer, "/sharing")
        response = viewer.post("/ai/suggest", data={
            "csrf": csrf, "document_id": document_id, "target_id": owner_id
        }, follow_redirects=False)
        assert response.status_code == 403


def test_unauthenticated_download_is_redirected_to_login():
    with TestClient(app) as client:
        response = client.get("/documents/1/download", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_ai_suggestion_does_not_grant_access_until_owner_approves():
    suffix = uuid.uuid4().hex[:10]
    password = "Demo-Password-82!Safe"
    owner_name = "own" + suffix
    viewer_name = "view" + suffix

    with TestClient(app) as owner, TestClient(app) as viewer:
        register_and_login(owner, owner_name, password)
        csrf = token(owner, "/upload")
        owner.post("/upload", data={"csrf": csrf}, files={
            "file": ("suggested.txt", b"restricted content", "text/plain")
        })

        with Session(engine) as db:
            doc = db.scalar(select(Document).where(
                Document.filename == "suggested.txt"
            ).order_by(Document.id.desc()))
            document_id = doc.id

        register_and_login(viewer, viewer_name, password)

        # The recipient cannot download before approval.
        assert viewer.get(
            f"/documents/{document_id}/download"
        ).status_code == 404

        # Only the owner can create and approve this suggestion.
        with Session(engine) as db:
            from app.main import User, Suggestion
            recipient = db.scalar(select(User).where(User.username == viewer_name))
            target_id = recipient.id

        csrf = token(owner, "/sharing")
        response = owner.post("/ai/suggest", data={
            "csrf": csrf, "document_id": document_id, "target_id": target_id
        }, follow_redirects=False)
        assert response.status_code == 303

        with Session(engine) as db:
            suggestion = db.scalar(select(Suggestion).where(
                Suggestion.document_id == document_id,
                Suggestion.target_id == target_id
            ).order_by(Suggestion.id.desc()))
            suggestion_id = suggestion.id
            assert db.scalar(select(Permission.id).where(
                Permission.document_id == document_id,
                Permission.user_id == target_id
            )) is None

        # The owner explicitly approves the suggestion.
        csrf = token(owner, "/sharing")
        response = owner.post(
            f"/ai/suggestions/{suggestion_id}/approve",
            data={"csrf": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303

        # Access is available only after approval.
        response = viewer.get(f"/documents/{document_id}/download")
        assert response.status_code == 200
        assert response.content == b"restricted content"

        # The recipient cannot approve another owner's suggestion.
        with TestClient(app) as stranger:
            register_and_login(stranger, "str" + suffix, password)
            csrf = token(stranger, "/dashboard")
            response = stranger.post(
                f"/ai/suggestions/{suggestion_id}/approve",
                data={"csrf": csrf},
                follow_redirects=False,
            )
            assert response.status_code == 404
