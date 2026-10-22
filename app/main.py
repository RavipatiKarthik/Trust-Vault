
import os
import secrets
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from html import escape

from fastapi import FastAPI, Request, Depends, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import (
    create_engine, String, Integer, ForeignKey, DateTime, Text, select
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from pwdlib import PasswordHash

BASE = Path(__file__).resolve().parent.parent
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)

DATABASE_URL = os.getenv(
    "DATABASE_URL", f"sqlite:///{(BASE / 'trustvault.db').as_posix()}"
)
SECRET_KEY = os.getenv("SESSION_SECRET")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
    print("WARNING: Temporary session secret. Set SESSION_SECRET before deployment.")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
password_hash = PasswordHash.recommended()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(80), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    access: Mapped[str] = mapped_column(String(20), default="viewer")


class Suggestion(Base):
    __tablename__ = "suggestions"
    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class Audit(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    document_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id"), nullable=True
    )
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


Base.metadata.create_all(engine)

app = FastAPI(title="TrustVault", version="1.0.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE", "false").lower() == "true",
)
app.mount("/static", StaticFiles(directory=BASE / "app" / "static"), name="static")


def get_db():
    with Session(engine) as db:
        yield db


def current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def audit(db, actor_id, action, document_id=None, detail=""):
    db.add(Audit(
        actor_id=actor_id,
        action=action,
        document_id=document_id,
        detail=detail[:2000],
    ))


def page(title, body, user=None, csrf=""):
    nav = ""
    if user:
        nav = f"""
        <nav>
          <a href="/dashboard">Dashboard</a>
          <a href="/documents">Documents</a>
          <a href="/sharing">Sharing & AI</a>
          <a href="/audit">Audit trail</a>
          <form method="post" action="/logout" class="inline">
            <input type="hidden" name="csrf" value="{escape(csrf)}">
            <button>Log out ({escape(user.username)})</button>
          </form>
        </nav>"""
    return HTMLResponse(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · TrustVault</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body><header><h1>🔐 TrustVault</h1>{nav}</header>
<main><h2>{escape(title)}</h2>{body}</main>
<footer>TrustVault · Secure document access</footer></body></html>""")


def csrf_token(request):
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]


async def read_form(request: Request):
    form = await request.form()
    expected = request.session.get("csrf")
    if not expected or not secrets.compare_digest(str(form.get("csrf", "")), expected):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return form


def login_required(request, db):
    user = current_user(request, db)
    if not user:
        return None
    return user


def can_read(db, user, doc):
    if user.id == doc.owner_id:
        return True
    return db.scalar(select(Permission.id).where(
        Permission.document_id == doc.id,
        Permission.user_id == user.id,
        Permission.access == "viewer",
    )) is not None


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse("/dashboard" if current_user(request, db) else "/login", 303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    token = csrf_token(request)
    return page("Create account", f"""
    <form method="post" action="/register">
      <input type="hidden" name="csrf" value="{token}">
      <label>Username <input name="username" minlength="3" maxlength="80" required></label>
      <label>Password <input name="password" type="password" minlength="12" required></label>
      <button>Create account</button>
    </form><p>Already registered? <a href="/login">Log in</a></p>""")


@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    form = await read_form(request)
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    if len(username) < 3 or len(username) > 80 or not username.isalnum():
        return page("Registration error", '<p>Use 3–80 letters or numbers for the username.</p><a href="/register">Try again</a>')
    if len(password) < 12:
        return page("Registration error", '<p>Password must be at least 12 characters.</p><a href="/register">Try again</a>')
    if db.scalar(select(User.id).where(User.username == username)):
        return page("Registration error", '<p>Username already exists.</p><a href="/register">Try again</a>')
    user = User(username=username, password=password_hash.hash(password), role="viewer")
    db.add(user)
    db.flush()
    audit(db, user.id, "account.registered", detail=f"username={username}")
    db.commit()
    return RedirectResponse("/login", 303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    token = csrf_token(request)
    return page("Log in", f"""
    <form method="post" action="/login">
      <input type="hidden" name="csrf" value="{token}">
      <label>Username <input name="username" required></label>
      <label>Password <input name="password" type="password" required></label>
      <button>Log in</button>
    </form><p>New here? <a href="/register">Create an account</a></p>""")


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await read_form(request)
    username, password = str(form.get("username", "")), str(form.get("password", ""))
    user = db.scalar(select(User).where(User.username == username))
    if not user or not password_hash.verify(password, user.password):
        return page("Login failed", '<p>Invalid username or password.</p><a href="/login">Try again</a>')
    request.session.clear()
    request.session["user_id"] = user.id
    csrf_token(request)
    audit(db, user.id, "auth.login")
    db.commit()
    return RedirectResponse("/dashboard", 303)


@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    await read_form(request)
    user = current_user(request, db)
    if user:
        audit(db, user.id, "auth.logout")
        db.commit()
    request.session.clear()
    return RedirectResponse("/login", 303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    owned = db.scalar(select(Document.id).where(Document.owner_id == user.id))
    shared = db.scalar(select(Permission.id).where(Permission.user_id == user.id))
    body = f"""
    <p>Welcome, <strong>{escape(user.username)}</strong>. Your account role is
    <strong>{escape(user.role)}</strong>.</p>
    <section class="cards">
      <a class="card" href="/documents"><h3>Documents</h3><p>Upload, list and securely download files.</p></a>
      <a class="card" href="/sharing"><h3>Sharing & AI</h3><p>Review access suggestions and permissions.</p></a>
      <a class="card" href="/audit"><h3>Audit trail</h3><p>Review recorded security events.</p></a>
    </section>
    <p><a href="/upload">＋ Upload a document</a></p>
    <p>Only the owner can approve access suggestions. Admin role alone does not grant access to private documents.</p>"""
    return page("Dashboard", body, user, csrf_token(request))


@app.get("/documents", response_class=HTMLResponse)
def documents(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    docs = db.scalars(select(Document).order_by(Document.id.desc())).all()
    visible = [d for d in docs if can_read(db, user, d)]
    items = "".join(
        f'<li><strong>{escape(d.filename)}</strong> — document #{d.id} '
        f'<a href="/documents/{d.id}/download">Download</a>'
        f' · <a href="/sharing?document_id={d.id}">Manage access</a></li>'
        for d in visible
    ) or "<li>No documents available to you yet.</li>"
    return page("Your documents", f'<p><a href="/upload">Upload document</a></p><ul>{items}</ul>', user, csrf_token(request))


@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    token = csrf_token(request)
    return page("Upload document", f"""
    <form method="post" action="/upload" enctype="multipart/form-data">
      <input type="hidden" name="csrf" value="{token}">
      <label>Choose file <input type="file" name="file" required></label>
      <p>Maximum file size: 10 MB.</p><button>Upload privately</button>
    </form>""", user, token)


@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    form = await read_form(request)
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    contents = await file.read(10 * 1024 * 1024 + 1)
    if not contents or len(contents) > 10 * 1024 * 1024:
        return page("Upload rejected", '<p>Choose a non-empty file no larger than 10 MB.</p><a href="/upload">Back</a>', user, csrf_token(request))
    safe_name = Path(file.filename or "document").name[:255]
    stored = uuid.uuid4().hex
    path = UPLOADS / stored
    path.write_bytes(contents)
    doc = Document(owner_id=user.id, filename=safe_name, stored_name=stored)
    db.add(doc)
    db.flush()
    audit(db, user.id, "document.uploaded", doc.id, f"filename={safe_name}")
    db.commit()
    return RedirectResponse("/documents", 303)


@app.get("/documents/{document_id}/download")
def download(document_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    doc = db.get(Document, document_id)
    if not doc or not can_read(db, user, doc):
        audit(db, user.id, "document.download_denied", document_id, "not found or not authorized")
        db.commit()
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Document not found")
    path = UPLOADS / doc.stored_name
    if not path.is_file():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Document file unavailable")
    audit(db, user.id, "document.downloaded", doc.id)
    db.commit()
    return FileResponse(path, filename=doc.filename, media_type="application/octet-stream")


@app.get("/sharing", response_class=HTMLResponse)
def sharing(request: Request, document_id: int | None = None, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    docs = db.scalars(select(Document).where(Document.owner_id == user.id)).all()
    options = "".join(
        f'<option value="{d.id}" {"selected" if d.id == document_id else ""}>{d.id}: {escape(d.filename)}</option>'
        for d in docs
    )
    users = db.scalars(select(User).where(User.id != user.id).order_by(User.username)).all()
    user_options = "".join(
        f'<option value="{u.id}">{escape(u.username)}</option>' for u in users
    )
    suggestions = db.scalars(select(Suggestion).where(
        Suggestion.owner_id == user.id
    ).order_by(Suggestion.id.desc())).all()
    suggestion_html = "".join(
        f'<li>Suggestion #{s.id} — document #{s.document_id}, target user #{s.target_id}: '
        f'{escape(s.reason)} — <strong>{escape(s.status)}</strong>'
        + (f'<form method="post" action="/ai/suggestions/{s.id}/approve" class="inline"><input type="hidden" name="csrf" value="{csrf_token(request)}"><button>Approve access</button></form><form method="post" action="/ai/suggestions/{s.id}/reject" class="inline"><input type="hidden" name="csrf" value="{csrf_token(request)}"><button>Reject</button></form>' if s.status == "pending" else "")
        + "</li>" for s in suggestions
    ) or "<li>No suggestions yet.</li>"
    body = f"""
    <h3>Request an AI-assisted suggestion</h3>
    <p>This initial version uses a transparent local rule, not an external LLM.
    It never grants access automatically. The owner must explicitly approve.</p>
    <form method="post" action="/ai/suggest">
      <input type="hidden" name="csrf" value="{csrf_token(request)}">
      <label>Owned document <select name="document_id" required>{options}</select></label>
      <label>Proposed recipient <select name="target_id" required>{user_options}</select></label>
      <button>Generate suggestion</button>
    </form>
    <h3>Pending and previous suggestions</h3><ul>{suggestion_html}</ul>
    <h3>Current access</h3>"""
    perms = db.scalars(select(Permission)).all()
    own_ids = {d.id for d in docs}
    current = [p for p in perms if p.document_id in own_ids]
    rows = "".join(
        f"<li>Document #{p.document_id} → user #{p.user_id}: {escape(p.access)}</li>"
        for p in current
    ) or "<li>No documents are currently shared.</li>"
    return page("Sharing & AI", body + f"<ul>{rows}</ul>", user, csrf_token(request))


@app.post("/ai/suggest")
async def suggest(request: Request, db: Session = Depends(get_db)):
    form = await read_form(request)
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    try:
        doc_id, target_id = int(form["document_id"]), int(form["target_id"])
    except (ValueError, KeyError, TypeError):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid document or user")
    doc, target = db.get(Document, doc_id), db.get(User, target_id)
    if not doc or doc.owner_id != user.id or not target or target.id == user.id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Only the document owner can request a suggestion")
    # Conservative recommendation: viewer-only, requiring explicit owner approval.
    reason = "Conservative baseline: propose viewer-only access. Confirm the recipient's need-to-know before approving."
    suggestion = Suggestion(document_id=doc.id, owner_id=user.id, target_id=target.id, reason=reason)
    db.add(suggestion)
    db.flush()
    audit(db, user.id, "ai.permission_suggested", doc.id, f"suggestion_id={suggestion.id}; target_id={target.id}; no access granted")
    db.commit()
    return RedirectResponse("/sharing", 303)


def decide_suggestion(request, db, suggestion_id, decision):
    user = login_required(request, db)
    if not user:
        return None
    suggestion = db.get(Suggestion, suggestion_id)
    if not suggestion or suggestion.owner_id != user.id:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Suggestion not found")
    if suggestion.status != "pending":
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail="Suggestion has already been decided")
    if decision == "approve":
        existing = db.scalar(select(Permission).where(
            Permission.document_id == suggestion.document_id,
            Permission.user_id == suggestion.target_id,
        ))
        if not existing:
            db.add(Permission(document_id=suggestion.document_id, user_id=suggestion.target_id, access="viewer"))
        suggestion.status = "approved"
        audit(db, user.id, "permission.approved", suggestion.document_id, f"suggestion_id={suggestion.id}; target_id={suggestion.target_id}")
    else:
        suggestion.status = "rejected"
        audit(db, user.id, "permission.rejected", suggestion.document_id, f"suggestion_id={suggestion.id}; target_id={suggestion.target_id}")
    db.commit()
    return user


@app.post("/ai/suggestions/{suggestion_id}/approve")
async def approve(suggestion_id: int, request: Request, db: Session = Depends(get_db)):
    await read_form(request)
    user = decide_suggestion(request, db, suggestion_id, "approve")
    return RedirectResponse("/login" if not user else "/sharing", 303)


@app.post("/ai/suggestions/{suggestion_id}/reject")
async def reject(suggestion_id: int, request: Request, db: Session = Depends(get_db)):
    await read_form(request)
    user = decide_suggestion(request, db, suggestion_id, "reject")
    return RedirectResponse("/login" if not user else "/sharing", 303)


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not user:
        return RedirectResponse("/login", 303)
    events = db.scalars(select(Audit).order_by(Audit.id.desc()).limit(200)).all()
    # Owners see their own events and events concerning documents they own.
    owned_ids = set(db.scalars(select(Document.id).where(Document.owner_id == user.id)).all())
    visible = [
        e for e in events
        if e.actor_id == user.id or (e.document_id is not None and e.document_id in owned_ids)
    ]
    rows = "".join(
        f"<tr><td>{e.id}</td><td>{escape(e.action)}</td><td>{e.document_id or '—'}</td>"
        f"<td>{escape(e.detail)}</td><td>{escape(e.created_at.isoformat())}</td></tr>"
        for e in visible
    ) or '<tr><td colspan="5">No events recorded yet.</td></tr>'
    return page("Audit trail", f"""
    <p>Latest events visible to your account (up to 200 recent system events).</p>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Action</th>
    <th>Document</th><th>Details</th><th>Time</th></tr></thead><tbody>{rows}</tbody></table></div>
    """, user, csrf_token(request))


@app.get("/health")
def health():
    return {"status": "ok"}
