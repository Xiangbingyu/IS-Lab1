import secrets
import pytest
from app import create_app, db
from app.models import Note, User
from app.security import hash_password


@pytest.fixture()
def app():
    application = create_app({"TESTING": True, "SECRET_KEY": secrets.token_hex(32),
                              "SQLALCHEMY_DATABASE_URI": "sqlite://",
                              "BCRYPT_ROUNDS": 4})
    with application.app_context():
        db.create_all()
        db.session.add_all([
            User(username="student", password_hash=hash_password("Study-Notes-2026!")),
            User(username="other", password_hash=hash_password("Other-Notes-2026!")),
        ])
        db.session.commit()
        db.session.add_all([Note(owner_id=1, title="JWT study", body="Verify signatures."),
                            Note(owner_id=2, title="Private", body="Other user's note.")])
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def token(client):
    return client.post("/auth/login", json={"username": "student", "password": "Study-Notes-2026!"}).json["access_token"]


@pytest.fixture()
def headers(token):
    return {"Authorization": f"Bearer {token}"}
