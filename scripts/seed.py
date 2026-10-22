
import os
from sqlalchemy import select
from app.main import Base, engine, Session, User, password_hash

Base.metadata.create_all(engine)

accounts = [
    ("owner_demo", os.getenv("SEED_OWNER_PASSWORD"), "owner"),
    ("viewer_demo", os.getenv("SEED_VIEWER_PASSWORD"), "viewer"),
    ("admin_demo", os.getenv("SEED_ADMIN_PASSWORD"), "admin"),
]

with Session(engine) as db:
    for username, password, role in accounts:
        if not password or len(password) < 12:
            raise SystemExit(
                f"Set {username.upper().replace('_DEMO', '')}_PASSWORD "
                "environment variable to a password of at least 12 characters."
            )
        user = db.scalar(select(User).where(User.username == username))
        if user:
            user.role = role
            user.password = password_hash.hash(password)
        else:
            db.add(User(
                username=username,
                password=password_hash.hash(password),
                role=role,
            ))
    db.commit()

print("Demo accounts created or updated successfully.")
print("Use the passwords supplied through your environment variables.")
