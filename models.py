import json
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    score = db.Column(db.Integer, default=0)
    grade = db.Column(db.String(2), default="F")

    findings_json = db.Column(db.Text, default="[]")
    meta_json = db.Column(db.Text, default="{}")

    duration_ms = db.Column(db.Integer, default=0)

    def set_findings(self, findings):
        self.findings_json = json.dumps(findings, ensure_ascii=False)

    def get_findings(self):
        try:
            return json.loads(self.findings_json)
        except (TypeError, ValueError):
            return []

    def set_meta(self, meta):
        self.meta_json = json.dumps(meta, ensure_ascii=False)

    def get_meta(self):
        try:
            return json.loads(self.meta_json)
        except (TypeError, ValueError):
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "score": self.score,
            "grade": self.grade,
            "findings": self.get_findings(),
            "meta": self.get_meta(),
            "duration_ms": self.duration_ms,
        }
