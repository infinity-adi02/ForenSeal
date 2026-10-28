import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditLog, now_utc


def append_audit(db: Session, *, actor_id: str, action: str, outcome: str, case_id: str | None = None,
                 evidence_id: str | None = None, reference: str | None = None) -> AuditLog:
    previous = db.scalar(select(AuditLog).order_by(AuditLog.sequence.desc()).limit(1))
    previous_hash = previous.entry_hash if previous else "0" * 64
    occurred_at = now_utc()
    record_fields = {"actor_id": actor_id, "action": action, "outcome": outcome, "case_id": case_id,
                     "evidence_id": evidence_id, "reference": reference, "previous_hash": previous_hash}
    fields = {**record_fields,
              "occurred_at": occurred_at.isoformat()}
    entry_hash = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    record = AuditLog(**record_fields, occurred_at=occurred_at, entry_hash=entry_hash)
    db.add(record)
    db.flush()
    return record


def verify_audit_chain(db: Session) -> bool:
    previous_hash = "0" * 64
    rows = db.scalars(select(AuditLog).order_by(AuditLog.sequence)).all()
    for row in rows:
        fields = {"actor_id": row.actor_id, "action": row.action, "outcome": row.outcome,
                  "case_id": row.case_id, "evidence_id": row.evidence_id, "reference": row.reference,
                  "occurred_at": row.occurred_at.isoformat(), "previous_hash": previous_hash}
        expected = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if row.previous_hash != previous_hash or row.entry_hash != expected:
            return False
        previous_hash = row.entry_hash
    return True
