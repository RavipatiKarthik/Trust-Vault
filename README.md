
# TrustVault — Secure Document Sharing

TrustVault is a Python and FastAPI web application for controlled document
sharing. It provides authentication, owner-controlled permissions, AI-assisted
sharing suggestions, and an audit log.

## Features

- User authentication with password hashing.
- Owner, viewer, and admin roles.
- Document upload and server-side download authorization.
- Private documents by default.
- AI-assisted sharing suggestions that do not grant access automatically.
- Owner approval or rejection of sharing suggestions.
- Audit events for security-relevant actions.
- Automated tests for cross-user document isolation.
- CSRF protection for form submissions.

## Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite for local development
- Starlette sessions
- Jinja2 templates
- HTML and CSS
- Pytest and FastAPI TestClient

## Project Structure

```text
trustvault/
├── app/
│   ├── main.py
│   ├── static/
│   │   └── style.css
│   └── templates/
├── scripts/
│   └── seed.py
├── tests/
│   └── test_document_access.py
├── uploads/
├── .env.example
├── .gitignore
├── PROMPTS.md
├── THREATS.md
├── README.md
└── requirements.txt
```

## Local Setup

Use Python 3.11 or a compatible version supported by the dependencies.

### 1. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 3. Configure environment variables

Generate a strong session secret:

```powershell
$env:SESSION_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep the secret private. For local development, set it in the same terminal
used to start the server.

### 4. Seed demo accounts

Set strong demo passwords in the terminal:

```powershell
$env:SEED_OWNER_PASSWORD = "Replace-With-Your-Owner-Password"
$env:SEED_VIEWER_PASSWORD = "Replace-With-Your-Viewer-Password"
$env:SEED_ADMIN_PASSWORD = "Replace-With-Your-Admin-Password"
python -m scripts.seed
```

Use your actual chosen passwords when logging in. Do not commit passwords
or production credentials to Git.

### 5. Start the application

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 in a browser.

### 6. Run automated tests

```powershell
python -m pytest -v
```

## Permission Model

- **Owner:** Can access their own documents and approve or reject sharing
  suggestions for documents they own.
- **Viewer:** Can access documents only when explicitly granted permission.
- **Admin:** Has an application role, but must not bypass document-level
  authorization unless a documented and tested policy explicitly permits it.

All document downloads must be authorized on the server. Hiding a download
link in the UI is not an access-control mechanism.

## AI-Assisted Sharing

The suggestion engine may recommend a potential recipient and provide a
reason. A suggestion alone must not create a permission. The owner must
approve the request before access is granted. Suggestions and decisions
should be recorded in the audit log.

The current suggestion engine is a conservative local rule-based prototype,
not a production AI model. Its recommendations may be incorrect and require
human review.

## Security Notes

See [THREATS.md](THREATS.md) for the threat model.

This project is a prototype. Before production use, review session
configuration, upload validation, database transactions, audit-log integrity,
HTTPS, deployment secrets, rate limiting, and backup/recovery procedures.

## API and Routes

The FastAPI application exposes browser routes for registration, login,
logout, documents, sharing suggestions, approval/rejection, and audit
inspection. Open `/docs` while the server is running to inspect registered
API routes. See `API.md` for the route and authorization guide.

## AI Usage and Development Log

See [PROMPTS.md](PROMPTS.md) for the AI-assisted development log, corrections,
and related commit references.

## Demo

For a demonstration, show:
1. Owner login and document upload.
2. A different user being denied access to a private document.
3. A sharing suggestion that does not grant access automatically.
4. Owner approval granting the intended viewer access.
5. Audit entries for the relevant actions.

## Limitations

- SQLite is intended for local development in this prototype.
- The suggestion engine is rule-based rather than a trained AI model.
- Audit records stored in the same database are not tamper-proof.
- Production deployment requires additional security and operational review.
