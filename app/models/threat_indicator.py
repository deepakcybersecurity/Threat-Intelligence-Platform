from datetime import datetime
from app import db
from app.models.associations import (
    report_indicator,
    malware_indicator,
)

class ThreatIndicator(db.Model):
    __tablename__ = "threat_indicators"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    indicator_value = db.Column(
        db.String(255),
        nullable=False
    )

    indicator_type = db.Column(
        db.String(50),
        nullable=False
    )

    confidence_score = db.Column(
        db.Integer,
        nullable=False,
        default=50
    )

    risk_score = db.Column(
        db.Integer,
        nullable=True,
        default=None
    )

    severity = db.Column(
        db.Enum(
            "Low",
            "Medium",
            "High",
            "Critical",
            name="severity_enum"
        ),
        nullable=False,
        default="Medium"
    )

    status = db.Column(
        db.Enum(
            "Active",
            "Inactive",
            "Expired",
            "False Positive",
            name="ioc_status_enum"
        ),
        nullable=False,
        default="Active"
    )

    source = db.Column(
        db.String(100),
        nullable=False
    )

    first_seen_at = db.Column(
        db.DateTime,
        nullable=True
    )

    last_seen_at = db.Column(
        db.DateTime,
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

    added_by_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    tlp_marking = db.Column(
        db.Enum(
            "RED",
            "AMBER",
            "GREEN",
            "WHITE",
            "CLEAR",
            name="tlp_enum"
        ),
        nullable=False,
        default="WHITE"
    )

    context = db.Column(
        db.Text,
        nullable=True
    )

    reports = db.relationship(
        "ThreatReport",
        secondary=report_indicator,
        back_populates="indicators",
        lazy=True
    )

    malwares = db.relationship(
        "Malware",
        secondary=malware_indicator,
        back_populates="indicators",
        lazy=True
    )

    alerts = db.relationship(
        "Alert",
        back_populates="indicator",
        cascade="all, delete-orphan",
        lazy=True
    )

    added_by = db.relationship(
        "User",
        back_populates="threat_indicators"
    )

    @property
    def value(self):
        return self.indicator_value

    @property
    def confidence(self):
        return self.confidence_score