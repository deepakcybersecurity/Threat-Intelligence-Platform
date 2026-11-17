from datetime import datetime
from app import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    severity = db.Column(
        db.Enum(
            "Low",
            "Medium",
            "High",
            "Critical",
            name="alert_severity_enum"
        ),
        nullable=False,
        default="Medium"
    )

    status = db.Column(
        db.Enum(
            "Open",
            "In Progress",
            "Resolved",
            "Closed",
            name="alert_status_enum"
        ),
        nullable=False,
        default="Open"
    )

    alert_type = db.Column(
        db.String(50),
        nullable=False,
        default="General"
    )

    is_read = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    malware_id = db.Column(
        db.Integer,
        db.ForeignKey("malware_info.id"),
        nullable=True
    )

    indicator_id = db.Column(
        db.Integer,
        db.ForeignKey("threat_indicators.id"),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    malware = db.relationship(
        "Malware",
        back_populates="alerts"
    )

    indicator = db.relationship(
        "ThreatIndicator",
        back_populates="alerts"
    )

    user = db.relationship(
        "User",
        back_populates="alerts"
    )