import hashlib
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import current_user
from ..config import settings
from ..database import get_db
from ..models import Batch, Evidence, Simulation, User
from ..services.audit_service import append_audit
from ..services.blockchain_service import BlockchainUnavailable, read_batch
from ..services.hashing_service import hash_file
from ..services.merkle_service import merkle_root
from ..services.fingerprint_access import fingerprint_access_granted

router = APIRouter(prefix="/api/simulations", tags=["attack simulator"])


class SimulationRequest(BaseModel):
    evidence_id: str
    scenario: str = Field(pattern="^(single_byte|missing|blockchain_failure)$")


def copy_stream(source: Path, destination: Path) -> None:
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)


@router.post("")
def run_simulation(body: SimulationRequest, db: Session = Depends(get_db),
                   fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                   user: User = Depends(current_user)):
    evidence = db.get(Evidence, body.evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    original_path = settings.storage_dir / evidence.storage_key
    if not original_path.is_file():
        raise HTTPException(status_code=410, detail="Original evidence is missing; simulation requires an available source file")
    simulation_id = str(uuid.uuid4())
    sim_dir = settings.storage_dir / "simulations"
    sim_dir.mkdir(parents=True, exist_ok=True)
    working_key = f"{simulation_id}.working"
    working_path = sim_dir / working_key
    copy_stream(original_path, working_path)
    if body.scenario == "single_byte":
        with working_path.open("r+b") as file:
            file.seek(0, 2)
            length = file.tell()
            if length == 0:
                file.write(b"\x01")
            else:
                position = length // 2
                file.seek(position)
                byte = file.read(1)
                file.seek(position)
                file.write(bytes([byte[0] ^ 1]))
    elif body.scenario == "missing":
        working_path.unlink()
    modified_hash = hash_file(working_path) if working_path.exists() else None
    if body.scenario == "missing":
        outcome = "MISSING"
    elif body.scenario == "blockchain_failure":
        outcome = "RPC_UNAVAILABLE_SIMULATED"
    else:
        outcome = "TAMPERED" if modified_hash != evidence.original_sha256 else "VERIFIED"
    sim = Simulation(id=simulation_id, evidence_id=evidence.id, scenario=body.scenario, working_key=working_key,
                     modified_sha256=modified_hash, outcome=outcome, created_by=user.id)
    db.add(sim)
    batch = db.get(Batch, evidence.batch_id) if evidence.batch_id else None
    chain_root = None
    chain_status = "NOT_ANCHORED"
    if batch:
        rows = db.query(Evidence).filter(Evidence.batch_id == batch.id).order_by(Evidence.id).all()
        changed_records = [(item.id, (modified_hash if item.id == evidence.id else item.original_sha256)) for item in rows]
        recomputed = merkle_root(changed_records)
        try:
            chain = read_batch(batch)
            if body.scenario == "blockchain_failure":
                chain_status = "RPC_UNAVAILABLE_SIMULATED"
            elif chain["anchored"]:
                chain_root = chain["root"]
                chain_status = "ANCHORED" if chain_root == batch.merkle_root else "ROOT_MISMATCH"
            else:
                chain_status = "BATCH_NOT_FOUND_ON_CHAIN"
        except BlockchainUnavailable:
            chain_status = "RPC_UNAVAILABLE"
    else:
        recomputed = None
    append_audit(db, actor_id=user.id, action="INSIDER_SIMULATION", outcome=outcome, case_id=evidence.case_id,
                 evidence_id=evidence.id, reference=simulation_id)
    db.commit()
    reveal = fingerprint_access_granted(fingerprint_code)
    return {"simulation_id": simulation_id, "scenario": body.scenario, "evidence_id": evidence.id,
            "original_sha256": evidence.original_sha256 if reveal else None, "modified_sha256": modified_hash,
            "original_merkle_root": batch.merkle_root if batch else None,
            "recomputed_merkle_root": recomputed, "anchored_root": chain_root,
            "blockchain_status": chain_status, "verification_result": outcome,
            "original_preserved": original_path.is_file() and hash_file(original_path) == evidence.original_sha256,
            "working_copy_retained": working_path.exists(),
            "audit_event": {"action": "INSIDER_SIMULATION", "outcome": outcome, "reference": simulation_id}}


@router.get("")
def list_simulations(limit: int = 50, db: Session = Depends(get_db), _user: User = Depends(current_user)):
    rows = db.query(Simulation).order_by(Simulation.created_at.desc()).limit(max(1, min(limit, 200))).all()
    return [{"id": row.id, "evidence_id": row.evidence_id, "scenario": row.scenario, "modified_sha256": row.modified_sha256,
             "outcome": row.outcome, "created_at": row.created_at} for row in rows]
