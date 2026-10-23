
from fastapi.testclient import TestClient
from app.main import app


def test_login_page_loads():
    client = TestClient(app)
    response = client.get("/login")
    assert response.status_code == 200


def test_dashboard_requires_login():
    client = TestClient(app)
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code in (302, 303, 401, 403)


def test_logout_requires_post():
    client = TestClient(app)
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 405
