from datetime import datetime
from app import db


class IPLookupHistory(db.Model):
    __tablename__ = "ip_lookup_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    country = db.Column(
        db.String(100),
        nullable=True
    )

    city = db.Column(
        db.String(100),
        nullable=True
    )

    isp = db.Column(
        db.String(150),
        nullable=True
    )

    organization = db.Column(
        db.String(150),
        nullable=True
    )

    lookup_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    user = db.relationship(
        "User",
        back_populates="ip_lookup_history"
    )