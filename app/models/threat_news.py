from datetime import datetime
from app import db

class ThreatNews(db.Model):
    __tablename__ = "threat_news"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(255),
        nullable=False
    )

    source = db.Column(
        db.String(150),
        nullable=False
    )

    source_url = db.Column(
        db.String(500),
        nullable=True
    )

    summary = db.Column(
        db.Text,
        nullable=True
    )

    category = db.Column(
        db.String(100),
        nullable=True,
        default="General"
    )

    published_at = db.Column(
        db.DateTime,
        nullable=True
    )

    severity = db.Column(
        db.Enum(
            "Low",
            "Medium",
            "High",
            "Critical",
            name="news_severity_enum"
        ),
        nullable=False,
        default="Low"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )