from app import db


# ThreatReport ↔ Malware
report_malware = db.Table(
    "report_malware",

    db.Column(
        "report_id",
        db.Integer,
        db.ForeignKey("threat_reports.id"),
        primary_key=True
    ),

    db.Column(
        "malware_id",
        db.Integer,
        db.ForeignKey("malware_info.id"),
        primary_key=True
    )
)


# ThreatReport ↔ ThreatIndicator
report_indicator = db.Table(
    "report_indicator",

    db.Column(
        "report_id",
        db.Integer,
        db.ForeignKey("threat_reports.id"),
        primary_key=True
    ),

    db.Column(
        "indicator_id",
        db.Integer,
        db.ForeignKey("threat_indicators.id"),
        primary_key=True
    )
)


# Malware ↔ ThreatIndicator
malware_indicator = db.Table(
    "malware_indicator",

    db.Column(
        "malware_id",
        db.Integer,
        db.ForeignKey("malware_info.id"),
        primary_key=True
    ),

    db.Column(
        "indicator_id",
        db.Integer,
        db.ForeignKey("threat_indicators.id"),
        primary_key=True
    )
)