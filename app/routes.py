import bcrypt
from flask import Blueprint, current_app, g, jsonify, render_template, request
from . import db
from .models import Note, User
from .security import issue_token, token_required

api = Blueprint("api", __name__)


@api.get("/")
def index():
    return render_template("index.html")


@api.get("/health")
def health():
    return jsonify(status="ok")


@api.post("/auth/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a JSON object"), 400
    username, password = data.get("username"), data.get("password")
    if (not isinstance(username, str) or not 1 <= len(username) <= 128
            or not isinstance(password, str) or not 1 <= len(password.encode()) <= 72):
        return jsonify(error="Invalid credentials"), 401
    user = db.session.scalar(db.select(User).where(User.username == username))
    hashed = user.password_hash if user else current_app.extensions["dummy_hash"]
    matches = bcrypt.checkpw(password.encode(), hashed)
    if not user or not matches:
        return jsonify(error="Invalid credentials"), 401
    # 'Bearer' is the public authentication scheme, not a hardcoded credential.
    return jsonify(access_token=issue_token(user), token_type="Bearer", expires_in=current_app.config["JWT_TTL_SECONDS"])  # nosec B106


@api.get("/api/data")
@api.get("/api/notes")
@token_required
def list_notes():
    query = request.args.get("q", "")
    if len(query) > 100:
        return jsonify(error="Search query must not exceed 100 characters"), 400
    statement = db.select(Note).where(Note.owner_id == g.user.id)
    if query:
        # Bound SQL parameters; literal % and _ cannot widen the search.
        statement = statement.where(Note.title.contains(query, autoescape=True))
    notes = db.session.scalars(statement.order_by(Note.id.desc()).limit(100)).all()
    return jsonify(notes=[note.as_dict() for note in notes])


@api.post("/api/notes")
@token_required
def create_note():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a JSON object"), 400
    title, body = data.get("title"), data.get("body")
    if (not isinstance(title, str) or not 1 <= len(title.strip()) <= 120
            or not isinstance(body, str) or not 1 <= len(body.strip()) <= 4000):
        return jsonify(error="Title: 1-120 characters; body: 1-4000 characters"), 400
    note = Note(owner_id=g.user.id, title=title.strip(), body=body.strip())
    db.session.add(note)
    db.session.commit()
    return jsonify(note=note.as_dict()), 201


@api.get("/api/notes/<int:note_id>")
@token_required
def get_note(note_id):
    if note_id >= 2**63:
        return jsonify(error="Note not found"), 404
    note = db.session.scalar(db.select(Note).where(
        Note.id == note_id, Note.owner_id == g.user.id))
    if note is None:
        return jsonify(error="Note not found"), 404
    return jsonify(note=note.as_dict())
