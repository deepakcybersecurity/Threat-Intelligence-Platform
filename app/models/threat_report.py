from datetime import datetime
from app import db
from app.models.associations import (
    report_malware ,
    report_indicator,
)

class ThreatReport(db.Model):
    __tablename__ = "threat_reports"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id"), 
        nullable=False
    )


    title = db.Column(
        db.String(200),
        nullable=False,
    )

    description= db.Column(
        db.Text,
        nullable=False,
    )

    category = db.Column(
        db.String(50),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="Open",
    )



    tlp_level = db.Column(
        db.String(20),
        nullable=False
    )

    target_sector = db.Column(
        db.String(150),
        nullable=False
    )

    attachment = db.Column(
        db.String(255),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )
    
    # relationships
    user = db.relationship(
        "User",
        back_populates="reports"
    )

    malwares = db.relationship(
        "Malware",
        secondary=report_malware,
        back_populates="reports",
        lazy=True
    )

    indicators = db.relationship(
        "ThreatIndicator",
        secondary=report_indicator,
        back_populates="reports",
        lazy=True
    )

    # def __repr__(self):
    # return f"<ThreatReport {self.title}>"

# def to_dict(self):
#     return {
#         "id": self.id,
#         "title": self.title,
#         "description": self.description,
#         "category": self.category,
#         "severity": self.severity,
#         "status": self.status,
#         "tlp_level": self.tlp_level,
#         "target_sector": self.target_sector,
#         "attachment": self.attachment,
#         "user": self.user.username if self.user else None,
#         "created_at": self.created_at.strftime("%d-%m-%Y")
#         if self.created_at else None,
#     }
