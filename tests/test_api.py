import secrets
from datetime import datetime, timezone
import bcrypt
import jwt
import pytest
from app import create_app, db
from app.models import User
from app.security import hash_password


def test_health_and_frontend(client):
    assert client.get("/health").json == {"status": "ok"}
    page = client.get("/")
    assert page.status_code == 200
    assert b"Secure Notes" in page.data


def test_login_token_claims(app, token):
    claims = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"],
                        audience="secure-notes", issuer="is-lab1")
    assert claims["sub"] == "1"
    assert claims["exp"] - claims["iat"] == 1800


@pytest.mark.parametrize("username,password", [
    ("student", "wrong"), ("missing", "wrong"), ("' OR '1'='1' --", "anything"),
])
def test_login_rejects_bad_credentials(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json == {"error": "Invalid credentials"}


@pytest.mark.parametrize("payload", [[], None, "text", 123])
def test_login_rejects_non_object_json(client, payload):
    assert client.post("/auth/login", json=payload).status_code == 400


@pytest.mark.parametrize("path,method", [("/api/data", "get"), ("/api/notes", "get"),
                                        ("/api/notes/1", "get"), ("/api/notes", "post")])
def test_all_private_endpoints_require_token(client, path, method):
    assert getattr(client, method)(path).status_code == 401


def test_bad_signature(client, token):
    parts = token.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    assert client.get("/api/data", headers={"Authorization": "Bearer " + ".".join(parts)}).status_code == 401


@pytest.mark.parametrize("variation", ["expired", "missing-exp", "wrong-aud", "wrong-iss", "future", "bad-sub", "huge-sub", "deleted", "none"])
def test_invalid_claims(app, client, variation):
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"sub": "1", "iat": now, "nbf": now, "exp": now + 1800,
              "iss": "is-lab1", "aud": "secure-notes"}
    if variation == "expired": claims["exp"] = now - 60
    if variation == "missing-exp": del claims["exp"]
    if variation == "wrong-aud": claims["aud"] = "another-app"
    if variation == "wrong-iss": claims["iss"] = "another-issuer"
    if variation == "future": claims["nbf"] = now + 3600
    if variation == "bad-sub": claims["sub"] = "abc"
    if variation == "huge-sub": claims["sub"] = "9" * 100
    if variation == "deleted": claims["sub"] = "999"
    token = jwt.encode(claims, "" if variation == "none" else app.config["SECRET_KEY"],
                       algorithm="none" if variation == "none" else "HS256")
    assert client.get("/api/data", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_owner_isolation_and_create(client, headers):
    notes = client.get("/api/data", headers=headers).json["notes"]
    assert len(notes) == 1 and notes[0]["title"] == "JWT study"
    assert client.get("/api/notes/2", headers=headers).status_code == 404
    response = client.post("/api/notes", headers=headers,
                           json={"title": "My note", "body": "Hello", "owner_id": 2})
    assert response.status_code == 201
    assert client.get(f"/api/notes/{response.json['note']['id']}", headers=headers).status_code == 200


@pytest.mark.parametrize("query", ["' OR '1'='1' --", "%", "_", "'; DROP TABLE note; --"])
def test_sqli_and_wildcards_are_literal(client, headers, query):
    response = client.get("/api/notes", query_string={"q": query}, headers=headers)
    assert response.status_code == 200 and response.json == {"notes": []}
    assert len(client.get("/api/data", headers=headers).json["notes"]) == 1


def test_normal_search(client, headers):
    assert len(client.get("/api/notes?q=JWT", headers=headers).json["notes"]) == 1


def test_xss_payload_remains_json_text(client, headers):
    payload = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
    response = client.post("/api/notes", headers=headers, json={"title": "XSS", "body": payload})
    assert response.status_code == 201
    assert response.mimetype == "application/json"
    assert response.json["note"]["body"] == payload
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("data", [{}, [], {"title": " ", "body": "ok"},
    {"title": 7, "body": "ok"}, {"title": "x" * 121, "body": "ok"},
    {"title": "ok", "body": "x" * 4001}])
def test_invalid_note_input(client, headers, data):
    assert client.post("/api/notes", headers=headers, json=data).status_code == 400


def test_request_and_query_limits(client, headers):
    assert client.post("/api/notes", headers=headers, json={"title": "x", "body": "a" * 17000}).status_code == 413
    assert client.get("/api/notes?q=" + "a" * 101, headers=headers).status_code == 400
    assert client.get("/api/notes/" + "9" * 100, headers=headers).status_code == 404


def test_bcrypt_salt_and_verification(app):
    with app.app_context():
        first = hash_password("Study-Notes-2026!")
        second = hash_password("Study-Notes-2026!")
        assert first != second
        assert bcrypt.checkpw(b"Study-Notes-2026!", first)
        assert first.startswith(b"$2b$")
        assert b"Study-Notes" not in db.session.get(User, 1).password_hash


def test_password_byte_limit(app):
    with app.app_context(), pytest.raises(ValueError):
        hash_password("a" * 73)


def test_security_headers(client):
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_missing_secret_fails_closed():
    with pytest.raises(RuntimeError):
        create_app({"SECRET_KEY": "short"})


def test_default_bcrypt_cost():
    application = create_app({"SECRET_KEY": secrets.token_hex(32)})
    assert application.extensions["dummy_hash"].startswith(b"$2b$12$")


def test_deleted_user_token(app, client, headers):
    with app.app_context():
        db.session.delete(db.session.get(User, 1))
        db.session.commit()
    assert client.get("/api/data", headers=headers).status_code == 401
