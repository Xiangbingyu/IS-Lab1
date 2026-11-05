from datetime import datetime, timezone
from . import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    def as_dict(self):
        # JSON carries plain text; HTML rendering must use a safe text sink.
        return {"id": self.id, "title": self.title, "body": self.body,
                "created_at": self.created_at.isoformat()}
