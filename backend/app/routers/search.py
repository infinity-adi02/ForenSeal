import re
import json
from difflib import SequenceMatcher
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..auth import current_user
from ..database import get_db
from ..models import AuditAnchor, AuditLog, Batch, Case, CustodyEvent, Evidence, Simulation, User, BenchmarkRun
from ..services.dataset_registry import SOURCES

router = APIRouter(prefix="/api/search", tags=["search"])


def _normalize(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _score(query: str, text: str) -> float:
    q = _normalize(query)
    target = _normalize(text)
    if not q or not target:
        return 0.0
    if q in target:
        return 1.0
    q_tokens = q.split()
    target_tokens = target.split()
    token_scores = [max((SequenceMatcher(None, token, candidate).ratio() for candidate in target_tokens), default=0.0)
                    for token in q_tokens]
    overlap = sum(score >= 0.65 for score in token_scores) / len(q_tokens)
    token_similarity = sum(token_scores) / len(token_scores)
    sequence_similarity = SequenceMatcher(None, q, target).ratio()
    return max(sequence_similarity, overlap * 0.88, token_similarity * (0.55 + 0.25 * overlap))


def _result(kind: str, title: str, detail: str, path: str, query: str, *searchable: str) -> dict | None:
    haystack = " ".join((title, detail, *searchable))
    score = _score(query, haystack)
    threshold = 0.48 if len(_normalize(query)) > 3 else 0.67
    if score < threshold:
        return None
    return {"kind": kind, "title": title, "detail": detail, "path": path, "score": round(score, 3)}


@router.get("")
def global_search(q: str = Query(min_length=2, max_length=120), limit: int = Query(default=12, ge=1, le=30),
                  db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = q.strip()
    if len(query) < 2:
        return {"query": query, "results": []}
    results: list[dict] = []

    cases = db.query(Case).all()
    case_lookup = {case.id: case.reference for case in cases}
    for case in cases:
        item = _result("Case", case.name, f"{case.reference} · {case.description}", f"/cases/{case.id}", query,
                       case.reference, case.description)
        if item:
            results.append(item)

    evidence_rows = db.query(Evidence).all()
    evidence_lookup = {evidence.id: evidence for evidence in evidence_rows}
    for evidence in evidence_rows:
        case_ref = case_lookup.get(evidence.case_id, "Unknown case")
        item = _result("Evidence", evidence.original_filename, f"{case_ref} · {evidence.source_name}",
                       f"/verification?id={quote(evidence.id)}", query, evidence.id, evidence.source_name,
                       evidence.source_url or "", evidence.source_scenario or "")
        if item:
            results.append(item)

    for batch in db.query(Batch).all():
        case_ref = case_lookup.get(batch.case_id, "Unknown case")
        item = _result("Batch", f"Batch {batch.id[:8]}", f"{case_ref} · {batch.status} · {batch.evidence_count} files",
                       "/batches", query, batch.id, batch.merkle_root, batch.manifest_commitment,
                       batch.transaction_hash or "", case_ref)
        if item:
            results.append(item)

    for event in db.query(CustodyEvent).order_by(CustodyEvent.created_at.desc()).limit(2000).all():
        evidence = evidence_lookup.get(event.evidence_id)
        title = f"{event.event_type.replace('_', ' ').title()} · {evidence.original_filename if evidence else event.evidence_id[:8]}"
        detail = f"{event.outcome} · {event.reason or 'No reason'} · {event.created_at.isoformat()}"
        item = _result("Custody event", title, detail,
                       f"/verification?id={quote(event.evidence_id)}", query,
                       event.id, event.evidence_id, event.actor_id, event.recipient or "",
                       event.blockchain_reference or "", event.reason or "")
        if item:
            results.append(item)

    for event in db.query(AuditLog).order_by(AuditLog.sequence.desc()).limit(2000).all():
        case_ref = case_lookup.get(event.case_id or "", "")
        detail = f"#{event.sequence} · {event.outcome} · {case_ref} · {event.occurred_at.isoformat()}"
        path = f"/verification?id={quote(event.evidence_id)}" if event.evidence_id else "/"
        item = _result("Audit event", event.action.replace("_", " ").title(), detail, path, query,
                       event.sequence.__str__(), event.action, event.outcome, event.reference or "",
                       event.actor_id, event.evidence_id or "", case_ref)
        if item:
            results.append(item)

    for anchor in db.query(AuditAnchor).order_by(AuditAnchor.created_at.desc()).limit(500).all():
        item = _result("Audit anchor", f"Audit anchor through #{anchor.through_sequence}",
                       f"Chain {anchor.chain_id} · transaction {anchor.transaction_hash}", "/reports", query,
                       anchor.commitment, anchor.contract_address, anchor.transaction_hash,
                       str(anchor.through_sequence))
        if item:
            results.append(item)

    for simulation in db.query(Simulation).order_by(Simulation.created_at.desc()).limit(2000).all():
        evidence = db.get(Evidence, simulation.evidence_id)
        item = _result("Simulation", f"{simulation.scenario.replace('_', ' ').title()} · {evidence.original_filename if evidence else simulation.evidence_id[:8]}",
                       f"{simulation.outcome} · {simulation.created_at.isoformat()}", "/simulator", query,
                       simulation.id, simulation.evidence_id, simulation.modified_sha256 or "")
        if item:
            results.append(item)

    if user.role == "administrator":
        for found_user in db.query(User).all():
            item = _result("User", found_user.username, found_user.role, "/users", query,
                           found_user.id, found_user.wallet_address or "", found_user.role)
            if item:
                results.append(item)

    for run in db.query(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).limit(200).all():
        try:
            sizes = ", ".join(str(result.get("size", "")) for result in json.loads(run.result_json))
        except (TypeError, ValueError):
            sizes = ""
        item = _result("Benchmark", f"Benchmark {run.id[:8]}", f"{run.status} · {run.created_at.isoformat()}",
                       "/benchmarks", query, run.id, sizes)
        if item:
            results.append(item)

    for source in SOURCES.values():
        item = _result("Dataset source", source["name"], source["purpose"], "/datasets", query,
                       source["url"], source["workflow"])
        if item:
            results.append(item)

    results.sort(key=lambda result: result["score"], reverse=True)
    return {"query": query, "results": results[:limit]}
