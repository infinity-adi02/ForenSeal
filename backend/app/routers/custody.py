import hashlib

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from web3 import Web3

from ..auth import current_user
from ..database import get_db
from ..models import CustodyEvent, Evidence, User
from ..schemas import CustodyCreate, TransferResolution
from ..services.audit_service import append_audit
from ..services.blockchain_service import BlockchainUnavailable, record_custody_event, resolve_custody_transfer

router = APIRouter(prefix="/api/evidence", tags=["chain of custody"])


@router.get("/{evidence_id}/custody")
def custody_timeline(evidence_id: str, db: Session = Depends(get_db), _user: User = Depends(current_user)):
    if db.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return db.query(CustodyEvent).filter(CustodyEvent.evidence_id == evidence_id).order_by(CustodyEvent.created_at).all()


@router.post("/{evidence_id}/custody")
def record_custody(evidence_id: str, body: CustodyCreate, db: Session = Depends(get_db), user: User = Depends(current_user)):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if body.event_type == "TRANSFER_INITIATED" and not body.recipient:
        raise HTTPException(status_code=422, detail="A recipient wallet address is required for a transfer")
    if body.event_type == "TRANSFER_INITIATED" and not Web3.is_address(body.recipient):
        raise HTTPException(status_code=422, detail="Transfer recipient must be an EVM wallet address")
    if body.event_type != "TRANSFER_INITIATED" and body.recipient:
        raise HTTPException(status_code=422, detail="Recipient is only valid for transfer initiation")
    chain_reference, transfer_id, _sequence = None, None, None
    chain_error = None
    try:
        chain_reference, transfer_id, _sequence = record_custody_event(
            evidence.id, body.event_type, user.wallet_address, body.recipient, body.reason)
    except (BlockchainUnavailable, ValueError, OSError, TimeoutError):
        pass
    except Exception as exc:
        # A chain/client mismatch must not turn a valid off-chain custody action into HTTP 500.
        chain_error = f"{type(exc).__name__}: {str(exc)[:180]}"
    outcome = ("PENDING_ACKNOWLEDGMENT_ON_CHAIN" if chain_reference else "PENDING_ACKNOWLEDGMENT_OFF_CHAIN") if body.event_type == "TRANSFER_INITIATED" else ("RECORDED_ON_CHAIN" if chain_reference else "RECORDED_OFF_CHAIN")
    event = CustodyEvent(evidence_id=evidence.id, actor_id=user.id, event_type=body.event_type,
                         outcome=outcome, recipient=Web3.to_checksum_address(body.recipient) if body.recipient else None,
                         reason=body.reason or None, blockchain_reference=chain_reference, chain_transfer_id=transfer_id)
    db.add(event)
    db.flush()
    append_audit(db, actor_id=user.id, action=body.event_type, outcome=event.outcome,
                 case_id=evidence.case_id, evidence_id=evidence.id,
                 reference=chain_error)
    db.commit()
    db.refresh(event)
    return event


@router.post("/custody/{event_id}/resolve")
def resolve_transfer(event_id: str, body: TransferResolution, db: Session = Depends(get_db), user: User = Depends(current_user)):
    event = db.get(CustodyEvent, event_id)
    if event is None or event.event_type != "TRANSFER_INITIATED":
        raise HTTPException(status_code=404, detail="Pending custody transfer not found")
    if not event.outcome.startswith("PENDING_ACKNOWLEDGMENT"):
        raise HTTPException(status_code=409, detail="Transfer has already been resolved")
    if not user.wallet_address or event.recipient != user.wallet_address:
        raise HTTPException(status_code=403, detail="Only the intended recipient may acknowledge this transfer")
    if event.blockchain_reference and event.chain_transfer_id:
        try:
            tx_hash = resolve_custody_transfer(event.evidence_id, event.chain_transfer_id,
                                               user.wallet_address, body.accepted, body.acknowledgment)
        except BlockchainUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Local EVM transfer acknowledgment failed ({type(exc).__name__})") from None
        event.blockchain_reference = tx_hash
        event.outcome = "ACCEPTED_ON_CHAIN" if body.accepted else "REJECTED_ON_CHAIN"
    else:
        event.outcome = "ACCEPTED_OFF_CHAIN" if body.accepted else "REJECTED_OFF_CHAIN"
    event.reason = (event.reason or "") + f"\nAcknowledgment SHA-256: {hashlib.sha256(body.acknowledgment.encode()).hexdigest()}"
    evidence = db.get(Evidence, event.evidence_id)
    append_audit(db, actor_id=user.id, action="TRANSFER_ACCEPTED" if body.accepted else "TRANSFER_REJECTED",
                 outcome=event.outcome, case_id=evidence.case_id, evidence_id=evidence.id,
                 reference=hashlib.sha256(body.acknowledgment.encode()).hexdigest())
    db.commit()
    db.refresh(event)
    return event
