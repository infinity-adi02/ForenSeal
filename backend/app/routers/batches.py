import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from web3 import Web3

from ..auth import current_user, require_roles
from ..database import get_db
from ..models import Batch, Case, Evidence, User
from ..schemas import BatchOut
from ..services.audit_service import append_audit
from ..services.blockchain_service import BlockchainUnavailable, anchor_batch, read_batch, transaction_details
from ..services.merkle_service import merkle_root

router = APIRouter(prefix="/api", tags=["batch anchoring"])


@router.get("/batches", response_model=list[BatchOut])
def list_batches(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    batches = db.query(Batch).order_by(Batch.created_at.desc()).all()
    results = []
    for batch in batches:
        item = BatchOut.model_validate(batch).model_dump()
        if batch.status != "ANCHORED":
            item["chain_status"] = "PENDING"
        else:
            try:
                chain = read_batch(batch)
                if not chain["anchored"]:
                    item["chain_status"] = "NOT_FOUND"
                elif (chain["root"] != batch.merkle_root or
                      chain["manifest_commitment"] != batch.manifest_commitment):
                    item["chain_status"] = "ROOT_MISMATCH"
                else:
                    item["chain_status"] = "ANCHORED_MATCH"
            except (BlockchainUnavailable, OSError, ValueError):
                item["chain_status"] = "RPC_UNAVAILABLE"
        results.append(item)
    return results


@router.post("/cases/{case_id}/batches", response_model=BatchOut, status_code=status.HTTP_201_CREATED)
def create_batch(case_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "collector"))):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    evidence = db.query(Evidence).filter(Evidence.case_id == case_id, Evidence.batch_id.is_(None)).order_by(Evidence.id).all()
    if not evidence:
        raise HTTPException(status_code=409, detail="No unbatched evidence is available for this case")
    records = [(item.id, item.original_sha256) for item in evidence]
    root = merkle_root(records)
    manifest = [{"evidence_id": identifier, "sha256": fingerprint} for identifier, fingerprint in records]
    commitment = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    batch = Batch(case_id=case_id, merkle_root=root, manifest_commitment=commitment,
                  evidence_count=len(evidence), status="PENDING", created_by=user.id)
    db.add(batch)
    db.flush()
    for item in evidence:
        item.batch_id = batch.id
    append_audit(db, actor_id=user.id, action="BATCH_CREATED", outcome="PENDING", case_id=case_id, reference=batch.id)
    try:
        tx_hash, address, chain_id = anchor_batch(batch)
        batch.transaction_hash, batch.contract_address, batch.chain_id = tx_hash, address, chain_id
        batch.status = "ANCHORED"
        append_audit(db, actor_id=user.id, action="BATCH_ANCHORED", outcome="SUCCESS", case_id=case_id,
                     reference=tx_hash)
    except (BlockchainUnavailable, OSError, ValueError, TimeoutError) as exc:
        # The commitment remains durable and pending. No transaction is claimed.
        batch.status = "PENDING"
        append_audit(db, actor_id=user.id, action="BATCH_ANCHOR_ATTEMPT", outcome="UNAVAILABLE",
                     case_id=case_id, reference=str(exc)[:240])
    db.commit()
    db.refresh(batch)
    return batch


@router.post("/batches/{batch_id}/anchor", response_model=BatchOut)
def retry_anchor(batch_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator"))):
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found")
    try:
        existing = read_batch(batch)
        if existing["anchored"]:
            if existing["root"] != batch.merkle_root or existing["manifest_commitment"] != batch.manifest_commitment:
                raise HTTPException(status_code=409, detail="On-chain commitment conflicts with the local immutable batch")
            batch.status = "ANCHORED"
            batch.chain_id = existing["chain_id"]
            batch.contract_address = existing["contract_address"]
        else:
            tx_hash, address, chain_id = anchor_batch(batch)
            batch.transaction_hash, batch.contract_address, batch.chain_id = tx_hash, address, chain_id
            batch.status = "ANCHORED"
        append_audit(db, actor_id=user.id, action="BATCH_ANCHORED", outcome="SUCCESS", case_id=batch.case_id,
                     reference=batch.transaction_hash or "on-chain commitment recovered")
        db.commit()
        db.refresh(batch)
        return batch
    except BlockchainUnavailable as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail=str(exc)) from None


@router.get("/blockchain/status")
def blockchain_status(_user: User = Depends(current_user)):
    from ..services.blockchain_service import status as get_status
    return get_status()


@router.get("/blockchain/transactions/{tx_hash}")
def get_transaction(tx_hash: str, _user: User = Depends(current_user)):
    if len(tx_hash.removeprefix("0x")) != 64:
        raise HTTPException(status_code=422, detail="Transaction hash must contain 32 bytes")
    try:
        return transaction_details(tx_hash)
    except BlockchainUnavailable as exc:
        return {"found": False, "status": "RPC_UNAVAILABLE", "reason": str(exc)}


@router.get("/batches/{batch_id}/chain-check")
def batch_chain_check(batch_id: str, db: Session = Depends(get_db), _user: User = Depends(current_user)):
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found")
    try:
        actual = read_batch(batch)
        actual["local_root"] = batch.merkle_root
        actual["root_matches"] = actual["root"] == batch.merkle_root if actual["root"] else False
        return actual
    except BlockchainUnavailable as exc:
        return {"available": False, "anchored": False, "root_matches": False, "reason": str(exc)}
