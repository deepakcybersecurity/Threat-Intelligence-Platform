from datetime import datetime
from app import db


class APICache(db.Model):
    __tablename__ = "api_cache"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    api_name = db.Column(
        db.String(100),
        nullable=False
    )

    endpoint = db.Column(
        db.String(255),
        nullable=False
    )

    response_data = db.Column(
        db.Text,
        nullable=False
    )

    cached_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )