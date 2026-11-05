"""Start a local evidence server with random, uncommitted credentials."""
import json
import secrets
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import create_app, db
from app.models import User
from app.security import hash_password
from waitress import serve

application = create_app({"SECRET_KEY": secrets.token_hex(32), "SQLALCHEMY_DATABASE_URI": "sqlite://"})
password = secrets.token_urlsafe(20)
with application.app_context():
    db.create_all()
    db.session.add_all([User(username="student", password_hash=hash_password(password)),
                        User(username="other", password_hash=hash_password(secrets.token_urlsafe(20)))])
    db.session.commit()
private = ROOT / "evidence" / "private"
private.mkdir(parents=True, exist_ok=True)
(private / "demo-login.json").write_text(json.dumps({"username": "student", "password": password}), encoding="utf-8")
print("Secure Notes evidence server: http://127.0.0.1:5081", flush=True)
serve(application, host="127.0.0.1", port=5081)
