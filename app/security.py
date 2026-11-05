import re
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request
from . import db
from .models import User


def valid_username(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{3,32}", value) is not None


def hash_password(password):
    if not isinstance(password, str) or not 12 <= len(password.encode("utf-8")) <= 72:
        raise ValueError("Password must contain 12-72 UTF-8 bytes.")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(current_app.config["BCRYPT_ROUNDS"]))


def issue_token(user):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": str(user.id), "iat": now, "nbf": now,
        "exp": now + timedelta(seconds=current_app.config["JWT_TTL_SECONDS"]),
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
    }, current_app.config["SECRET_KEY"], algorithm="HS256")


def token_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        parts = request.headers.get("Authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify(error="Authentication required"), 401
        try:
            claims = jwt.decode(
                parts[1], current_app.config["SECRET_KEY"], algorithms=["HS256"],
                issuer=current_app.config["JWT_ISSUER"],
                audience=current_app.config["JWT_AUDIENCE"],
                options={"require": ["sub", "iat", "nbf", "exp", "iss", "aud"]},
            )
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject.isascii() or not subject.isdigit():
                raise ValueError("Invalid subject")
            user_id = int(subject)
            if not 0 < user_id < 2**63:
                raise ValueError("Invalid subject")
            g.user = db.session.get(User, user_id)
            if g.user is None:
                raise ValueError("Deleted user")
        except (jwt.InvalidTokenError, ValueError, TypeError):
            return jsonify(error="Invalid or expired token"), 401
        return function(*args, **kwargs)
    return wrapped
