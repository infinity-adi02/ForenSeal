from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user
from ..auth import require_roles
from ..database import get_db
from ..models import AuditAnchor, AuditLog, User
from ..schemas import AuditOut
from ..services.audit_service import verify_audit_chain
from ..services.blockchain_service import BlockchainUnavailable, anchor_audit, read_audit_commitment

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(limit: int = 100, db: Session = Depends(get_db), _user: User = Depends(current_user)):
    return db.query(AuditLog).order_by(AuditLog.sequence.desc()).limit(max(1, min(limit, 500))).all()


@router.get("/verify")
def audit_status(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    latest = db.scalar(select(AuditAnchor).order_by(AuditAnchor.through_sequence.desc()).limit(1))
    if latest is None:
        return {"valid": verify_audit_chain(db), "blockchain_status": "NOT_ANCHORED", "latest_anchor": None}
    anchored_row = db.get(AuditLog, latest.through_sequence)
    local_anchor_matches = anchored_row is not None and anchored_row.entry_hash == latest.commitment
    try:
        chain = read_audit_commitment(latest.through_sequence)
        chain["matches_local_commitment"] = chain["commitment"] == latest.commitment and local_anchor_matches
        chain["blockchain_status"] = "ANCHORED_MATCH" if chain["matches_local_commitment"] else "ROOT_MISMATCH"
    except BlockchainUnavailable:
        chain = {"blockchain_status": "RPC_UNAVAILABLE", "matches_local_commitment": False}
    return {"valid": verify_audit_chain(db), "blockchain": chain,
            "latest_anchor": {"through_sequence": latest.through_sequence, "commitment": latest.commitment,
                              "transaction_hash": latest.transaction_hash, "chain_id": latest.chain_id,
                              "contract_address": latest.contract_address}}


@router.get("/anchors")
def list_anchors(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    return db.scalars(select(AuditAnchor).order_by(AuditAnchor.through_sequence.desc())).all()


@router.post("/anchor")
def commit_audit(db: Session = Depends(get_db), admin: User = Depends(require_roles("administrator"))):
    if not verify_audit_chain(db):
        raise HTTPException(status_code=409, detail="Audit hash chain failed verification")
    latest = db.scalar(select(AuditLog).order_by(AuditLog.sequence.desc()).limit(1))
    if latest is None:
        raise HTTPException(status_code=409, detail="There are no audit records to anchor")
    previous = db.get(AuditAnchor, latest.sequence)
    if previous:
        raise HTTPException(status_code=409, detail="This audit sequence has already been anchored")
    try:
        tx_hash, address, chain_id = anchor_audit(latest.sequence, latest.entry_hash)
    except (BlockchainUnavailable, OSError, ValueError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    row = AuditAnchor(through_sequence=latest.sequence, commitment=latest.entry_hash, chain_id=chain_id,
                      contract_address=address, transaction_hash=tx_hash)
    db.add(row)
    append_audit(db, actor_id=admin.id, action="AUDIT_LOG_ANCHORED", outcome="SUCCESS", reference=tx_hash)
    db.commit()
    return {"through_sequence": latest.sequence, "commitment": latest.entry_hash, "chain_id": chain_id,
            "contract_address": address, "transaction_hash": tx_hash}
