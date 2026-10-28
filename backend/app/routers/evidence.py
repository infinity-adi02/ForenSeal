import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..auth import current_user, require_roles
from ..config import settings
from ..database import get_db
from ..models import Case, CustodyEvent, Evidence, User
from ..schemas import EvidenceOut, VerificationOut
from ..services.audit_service import append_audit
from ..services.hashing_service import hash_file
from ..services.evidence_service import persist_upload
from ..services.merkle_service import inclusion_proof, verify_inclusion
from ..services.blockchain_service import BlockchainUnavailable, read_batch, record_custody_event
from ..services.dataset_registry import declared_source
from ..services.fingerprint_access import fingerprint_access_granted

router = APIRouter(prefix="/api", tags=["evidence"])


def _evidence_response(evidence: Evidence, fingerprint_code: str | None) -> EvidenceOut:
    result = EvidenceOut.model_validate(evidence)
    if not fingerprint_access_granted(fingerprint_code):
        result = result.model_copy(update={"original_sha256": None})
    return result


@router.post("/cases/{case_id}/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
async def upload_evidence(case_id: str, file: UploadFile = File(...), source_id: str = Form(default="user_upload"),
                          source_scenario: str | None = Form(default=None),
                          fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                          db: Session = Depends(get_db),
                          user: User = Depends(require_roles("administrator", "collector"))):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    source = declared_source(source_id) if source_id != "user_upload" else None
    if source_id != "user_upload" and source is None:
        raise HTTPException(status_code=422, detail="Choose a source from the registered public source list")
    if source_scenario and len(source_scenario) > 2000:
        raise HTTPException(status_code=422, detail="Scenario metadata must be 2000 characters or fewer")
    stored = await persist_upload(file, settings.storage_dir, settings.max_upload_bytes)
    destination = settings.storage_dir / stored["storage_key"]
    try:
        evidence = Evidence(case_id=case.id, original_filename=stored["filename"],
                            storage_key=stored["storage_key"], size_bytes=stored["size_bytes"],
                            mime_type=stored["mime_type"], original_sha256=stored["sha256"],
                            source_id=source_id,
                            source_name=source["name"] if source else "Unspecified local file",
                            source_url=source["url"] if source else None,
                            source_scenario=(source_scenario.strip() or None) if source_scenario else None,
                            collector_id=user.id, status="ORIGINAL")
        db.add(evidence)
        db.flush()
        collection_tx = None
        try:
            collection_tx, _transfer_id, _sequence = record_custody_event(evidence.id, "COLLECTION", user.wallet_address, None, "Evidence collected")
        except (BlockchainUnavailable, ValueError, OSError, TimeoutError):
            pass
        db.add(CustodyEvent(evidence_id=evidence.id, actor_id=user.id, event_type="COLLECTION",
                            outcome="RECORDED_ON_CHAIN" if collection_tx else "RECORDED_OFF_CHAIN",
                            reason="Evidence collected", blockchain_reference=collection_tx))
        append_audit(db, actor_id=user.id, action="EVIDENCE_COLLECTED", outcome="SUCCESS", case_id=case.id,
                     evidence_id=evidence.id, reference=stored["storage_key"])
        db.commit()
        db.refresh(evidence)
        return _evidence_response(evidence, fingerprint_code)
    except Exception:
        db.rollback()
        destination.unlink(missing_ok=True)
        raise


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(case_id: str, db: Session = Depends(get_db),
                  fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                  _user: User = Depends(current_user)):
    if db.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    rows = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.created_at.desc()).all()
    return [_evidence_response(item, fingerprint_code) for item in rows]


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: str, db: Session = Depends(get_db),
                 fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                 _user: User = Depends(current_user)):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return _evidence_response(evidence, fingerprint_code)


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    path = settings.storage_dir / evidence.storage_key
    if not path.is_file():
        append_audit(db, actor_id=user.id, action="EVIDENCE_DOWNLOAD", outcome="MISSING", case_id=evidence.case_id, evidence_id=evidence.id)
        db.commit()
        raise HTTPException(status_code=410, detail="Stored evidence file is missing")
    append_audit(db, actor_id=user.id, action="EVIDENCE_DOWNLOAD", outcome="SUCCESS", case_id=evidence.case_id, evidence_id=evidence.id)
    db.commit()
    return FileResponse(path, filename=evidence.original_filename, media_type="application/octet-stream")


@router.post("/evidence/{evidence_id}/verify", response_model=VerificationOut)
def verify_evidence(evidence_id: str, db: Session = Depends(get_db),
                    fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                    user: User = Depends(current_user)):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    path = settings.storage_dir / evidence.storage_key
    current_hash = hash_file(path) if path.is_file() else None
    matches = current_hash == evidence.original_sha256
    result_status = "VERIFIED" if matches else ("MISSING" if current_hash is None else "TAMPERED")
    message = {"VERIFIED": "Stored file matches its ingestion fingerprint.",
               "MISSING": "Stored file is missing; it cannot be verified.",
               "TAMPERED": "Stored file fingerprint differs from the immutable ingestion fingerprint."}[result_status]
    proof_valid = None
    anchored_root = None
    root_matches = None
    blockchain_status = "NOT_ANCHORED"
    if evidence.batch_id:
        from ..models import Batch
        batch = db.get(Batch, evidence.batch_id)
        if batch:
            siblings = db.query(Evidence).filter(Evidence.batch_id == batch.id).order_by(Evidence.id).all()
            leaves = [(item.id, item.original_sha256) for item in siblings]
            try:
                proof = inclusion_proof(leaves, evidence.id)
                proof_valid = verify_inclusion(evidence.id, evidence.original_sha256,
                                               [{"sibling_hash": node.sibling_hash, "sibling_side": node.sibling_side} for node in proof], batch.merkle_root)
            except ValueError:
                proof_valid = False
            try:
                chain = read_batch(batch)
                if chain["anchored"]:
                    anchored_root = chain["root"]
                    root_matches = anchored_root == batch.merkle_root
                    blockchain_status = "ANCHORED" if root_matches else "ROOT_MISMATCH"
                else:
                    blockchain_status = "BATCH_NOT_FOUND_ON_CHAIN"
            except (BlockchainUnavailable, OSError, ValueError):
                blockchain_status = "RPC_UNAVAILABLE"
    append_audit(db, actor_id=user.id, action="EVIDENCE_VERIFIED", outcome=result_status,
                 case_id=evidence.case_id, evidence_id=evidence.id)
    db.commit()
    reveal = fingerprint_access_granted(fingerprint_code)
    return VerificationOut(evidence_id=evidence.id, original_hash=evidence.original_sha256 if reveal else None,
                           current_hash=current_hash if reveal else None,
                           hash_match=matches, status=result_status, verified_at=datetime.now(timezone.utc), message=message,
                           merkle_proof_valid=proof_valid, anchored_root=anchored_root, root_matches=root_matches,
                           blockchain_status=blockchain_status)


@router.post("/evidence/{evidence_id}/verify-upload", response_model=VerificationOut)
async def verify_uploaded_candidate(evidence_id: str, file: UploadFile = File(...),
                                   db: Session = Depends(get_db),
                                   fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                                   user: User = Depends(current_user)):
    """Compare uploaded candidate bytes with an evidence item's original SHA-256; never store the candidate."""
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    digest = hashlib.sha256()
    size = 0
    while chunk := await file.read(1024 * 1024):
        size += len(chunk)
        if size > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail=f"Verification file exceeds the {settings.max_upload_bytes}-byte limit")
        digest.update(chunk)
    current_hash = digest.hexdigest()
    matches = current_hash == evidence.original_sha256
    result_status = "VERIFIED" if matches else "TAMPERED"
    message = ("Uploaded file bytes match the original evidence SHA-256 fingerprint."
               if matches else "Uploaded file bytes differ from the original evidence SHA-256 fingerprint.")
    proof_valid = None
    anchored_root = None
    root_matches = None
    blockchain_status = "NOT_ANCHORED"
    if evidence.batch_id:
        from ..models import Batch
        batch = db.get(Batch, evidence.batch_id)
        if batch:
            siblings = db.query(Evidence).filter(Evidence.batch_id == batch.id).order_by(Evidence.id).all()
            leaves = [(item.id, item.original_sha256) for item in siblings]
            try:
                proof = inclusion_proof(leaves, evidence.id)
                proof_valid = verify_inclusion(evidence.id, evidence.original_sha256,
                                               [{"sibling_hash": node.sibling_hash, "sibling_side": node.sibling_side} for node in proof], batch.merkle_root)
            except ValueError:
                proof_valid = False
            try:
                chain = read_batch(batch)
                if chain["anchored"]:
                    anchored_root = chain["root"]
                    root_matches = anchored_root == batch.merkle_root
                    blockchain_status = "ANCHORED" if root_matches else "ROOT_MISMATCH"
                else:
                    blockchain_status = "BATCH_NOT_FOUND_ON_CHAIN"
            except (BlockchainUnavailable, OSError, ValueError):
                blockchain_status = "RPC_UNAVAILABLE"
    db.add(CustodyEvent(evidence_id=evidence.id, actor_id=user.id, event_type="VERIFICATION",
                        outcome=result_status, reason="Uploaded candidate compared to original SHA-256"))
    append_audit(db, actor_id=user.id, action="EVIDENCE_CANDIDATE_VERIFIED", outcome=result_status,
                 case_id=evidence.case_id, evidence_id=evidence.id, reference=file.filename or "uploaded candidate")
    db.commit()
    reveal = fingerprint_access_granted(fingerprint_code)
    return VerificationOut(evidence_id=evidence.id, original_hash=evidence.original_sha256 if reveal else None,
                           current_hash=current_hash if reveal else None, hash_match=matches, status=result_status,
                           verified_at=datetime.now(timezone.utc), message=message,
                           merkle_proof_valid=proof_valid, anchored_root=anchored_root,
                           root_matches=root_matches, blockchain_status=blockchain_status,
                           candidate_filename=file.filename, candidate_size_bytes=size)
