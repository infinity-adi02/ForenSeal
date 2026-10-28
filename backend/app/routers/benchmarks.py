import json
import csv
import io
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import current_user, require_roles
from ..database import get_db
from ..models import BenchmarkRun, User
from ..services.blockchain_service import BlockchainUnavailable, run_benchmark

router = APIRouter(prefix="/api/benchmarks", tags=["benchmarks"])


class BenchmarkRequest(BaseModel):
    sizes: list[int] = Field(default_factory=lambda: [1, 10, 100], min_length=1, max_length=5)
    include_large: bool = False


@router.get("")
def history(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    rows = db.query(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).limit(20).all()
    return [{"id": row.id, "status": row.status, "created_at": row.created_at, "results": json.loads(row.result_json)} for row in rows]


@router.post("/run")
def benchmark(body: BenchmarkRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator"))):
    allowed = {1, 10, 100, 1000, 10000}
    if len(set(body.sizes)) != len(body.sizes) or any(size not in allowed for size in body.sizes):
        raise HTTPException(status_code=422, detail="Sizes must be unique values from 1, 10, 100, 1000, 10000")
    if any(size >= 1000 for size in body.sizes) and not body.include_large:
        raise HTTPException(status_code=422, detail="1000 and 10000 record runs require include_large=true; each performs that many real EVM transactions")
    results = []
    for size in body.sizes:
        try:
            results.append(run_benchmark(size))
        except (BlockchainUnavailable, OSError, ValueError, TimeoutError) as exc:
            results.append({"size": size, "success": False, "error": str(exc), "measured": False})
    row = BenchmarkRun(status="COMPLETE" if all(x["success"] for x in results) else "PARTIAL",
                       result_json=json.dumps(results), created_by=user.id)
    db.add(row)
    db.commit()
    return {"id": row.id, "status": row.status, "results": results,
            "note": "Gas and timings come from observed local EVM transaction receipts. Monetary cost is omitted because no gas-price or currency-conversion inputs were configured."}


@router.get("/{run_id}/csv")
def benchmark_csv(run_id: str, db: Session = Depends(get_db), _user: User = Depends(current_user)):
    row = db.get(BenchmarkRun, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Benchmark run not found")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["run_id", "network", "chain_id", "contract_address", "batch_size", "method", "transaction_hash", "gas_used", "success", "elapsed_transaction_group_seconds", "offchain_merkle_compute_seconds", "offchain_proof_verify_seconds"])
    for result in json.loads(row.result_json):
        if not result.get("success"):
            writer.writerow([row.id, result.get("network", ""), result.get("chain_id", ""), result.get("contract_address", ""), result.get("size", ""), "ERROR", "", "", False, "", "", ""])
            continue
        shared = [row.id, result["network"], result["chain_id"], result["contract_address"], result["size"]]
        individual = result["individual"]
        for receipt in individual["receipts"]:
            writer.writerow([*shared, "per_file", receipt["transaction_hash"], receipt["gas_used"], receipt.get("success", True), individual["elapsed_seconds"], result["offchain_merkle_seconds"], result["verification_seconds"]])
        batch = result["batched"]
        writer.writerow([*shared, "merkle_batch", batch["transaction_hash"], batch["total_gas"], batch.get("success", True), batch["elapsed_seconds"], result["offchain_merkle_seconds"], result["verification_seconds"]])
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="benchmark-{run_id}.csv"'})
