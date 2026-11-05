"""Secure Notes: a small Flask application for Information Security Lab 1."""
import os
import secrets
from pathlib import Path

import bcrypt
import click
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import HTTPException

db = SQLAlchemy()


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("LAB1_SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI="sqlite:///notes.db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        JWT_ISSUER="is-lab1", JWT_AUDIENCE="secure-notes", JWT_TTL_SECONDS=1800,
        BCRYPT_ROUNDS=12, MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)
    secret = app.config["SECRET_KEY"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise RuntimeError("Set LAB1_SECRET_KEY to a random secret of at least 32 bytes.")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    # A valid dummy hash makes unknown-account login perform a bcrypt check too.
    app.extensions["dummy_hash"] = bcrypt.hashpw(
        secrets.token_bytes(32), bcrypt.gensalt(rounds=app.config["BCRYPT_ROUNDS"])
    )
    from .routes import api
    app.register_blueprint(api)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    @app.cli.command("init-db")
    def init_db():
        """Create tables; never overwrite existing data."""
        db.create_all()
        click.echo("Database tables ready.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option()
    def create_user(username, password):
        """Create a user with an interactive password (not a shell argument)."""
        from .models import User
        from .security import hash_password, valid_username
        if not valid_username(username):
            raise click.ClickException("Username: 3-32 ASCII letters, digits or underscores.")
        if db.session.scalar(db.select(User).where(User.username == username)):
            raise click.ClickException("User already exists.")
        try:
            hashed = hash_password(password)
        except ValueError as error:
            raise click.ClickException(str(error)) from error
        db.session.add(User(username=username, password_hash=hashed))
        db.session.commit()
        click.echo("User created; password stored as a bcrypt hash.")

    return app
