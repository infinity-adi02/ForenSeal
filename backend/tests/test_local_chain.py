import hashlib
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.config import settings
from app.database import Base, get_db
from app.main import app
from app.models import Batch, User
from app.services.blockchain_service import (BlockchainUnavailable, anchor_audit, anchor_batch,
    DEPLOYMENT_FILE, load_contract, provider, read_audit_commitment, read_batch, record_custody_event,
    resolve_custody_transfer, run_benchmark, transaction_details)


def test_load_contract_reports_missing_deployment_as_actionable_error(tmp_path, monkeypatch):
    config = {"chainId": 31337, "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "abi": []}
    deployment_file = tmp_path / "contract_deployment.json"
    deployment_file.write_text(json.dumps(config))
    monkeypatch.setattr("app.services.blockchain_service.DEPLOYMENT_FILE", deployment_file)

    class EmptyCodeEth:
        chain_id = config["chainId"]

        @staticmethod
        def get_code(_address):
            return b""

    class FakeWeb3:
        eth = EmptyCodeEth()

    with pytest.raises(BlockchainUnavailable, match="No EvidenceLedger contract is deployed"):
        load_contract(FakeWeb3())


def test_real_local_evm_receipts_and_contract_reads():
    try:
        w3 = provider()
        load_contract(w3)
    except BlockchainUnavailable:
        pytest.skip("Start Hardhat and deploy EvidenceLedger to run local-chain integration")

    case_id = str(uuid.uuid4())
    batch = Batch(id=str(uuid.uuid4()), case_id=case_id, merkle_root=hashlib.sha256(b"root").hexdigest(),
                  manifest_commitment=hashlib.sha256(b"manifest").hexdigest(), evidence_count=1)
    tx_hash, address, chain_id = anchor_batch(batch)
    chain = read_batch(batch)
    assert chain["anchored"] is True
    assert chain["root"] == batch.merkle_root
    assert address == chain["contract_address"]
    assert chain_id == chain["chain_id"]
    receipt = transaction_details(tx_hash)
    assert receipt["status"] == "SUCCESS"
    assert receipt["gas_used"] > 0
    assert any(event["event"] == "BatchRootAnchored" for event in receipt["events"])

    audit_commitment = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    sequence = int.from_bytes(uuid.uuid4().bytes[:8], "big") or 1
    audit_tx, _, _ = anchor_audit(sequence, audit_commitment)
    assert read_audit_commitment(sequence)["commitment"] == audit_commitment
    assert transaction_details(audit_tx)["status"] == "SUCCESS"

    evidence_id = str(uuid.uuid4())
    recipient = w3.eth.accounts[1]
    transfer_tx, transfer_id, event_sequence = record_custody_event(evidence_id, "TRANSFER_INITIATED", None,
                                                                   recipient, "Forensic review transfer")
    assert transfer_id and event_sequence > 0
    assert transaction_details(transfer_tx)["status"] == "SUCCESS"
    resolution_tx = resolve_custody_transfer(evidence_id, transfer_id, recipient, True, "Evidence received")
    assert transaction_details(resolution_tx)["status"] == "SUCCESS"

    benchmark = run_benchmark(1)
    assert benchmark["success"] is True
    assert benchmark["individual"]["total_gas"] > 0
    assert benchmark["batched"]["total_gas"] > 0


def test_dataset_import_anchor_tamper_and_pdf_acceptance(tmp_path, monkeypatch):
    try:
        w3 = provider()
        load_contract(w3)
    except BlockchainUnavailable:
        pytest.skip("Start Hardhat and deploy EvidenceLedger to run dataset anchoring acceptance")

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(settings, "storage_dir", tmp_path)
    monkeypatch.setattr(settings, "max_upload_bytes", 1024 * 1024)
    with TestingSession() as db:
        db.add(User(id=str(uuid.uuid4()), username="datasetadmin", password_hash=hash_password("test-password"), role="administrator"))
        db.commit()

    def override_db():
        with TestingSession() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            login = client.post("/api/auth/login", json={"username": "datasetadmin", "password": "test-password"})
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            records = []
            fixtures = [
                ("BOTS fixture case", "BOTS-T", "botsv3", "selected-events.csv", b"time,event\n2024-01-01,synthetic-bots-fixture\n", {}),
                ("OTRF fixture case", "OTRF-T", "otrf", "scenario.jsonl", b'{"fixture":"synthetic-otrf","event":"process-start"}\n', {"source_scenario": "synthetic test scenario"}),
            ]
            for name, reference, source_id, filename, payload, extra in fixtures:
                case = client.post("/api/cases", headers=headers, json={"name": name, "reference": reference}).json()
                form = {"source_id": source_id, **extra}
                uploaded = client.post(f"/api/cases/{case['id']}/evidence", headers=headers, data=form,
                                       files={"file": (filename, payload, "application/octet-stream")})
                assert uploaded.status_code == 201
                evidence = uploaded.json()
                assert evidence["original_sha256"] == hashlib.sha256(payload).hexdigest()
                batch = client.post(f"/api/cases/{case['id']}/batches", headers=headers)
                assert batch.status_code == 201
                assert batch.json()["status"] == "ANCHORED"
                assert batch.json()["transaction_hash"]
                records.append((case, evidence, batch.json()))

            case, evidence, batch = records[0]
            comparison = client.post(f"/api/evidence/{evidence['id']}/verify-upload", headers=headers,
                                     files={"file": ("modified-copy.bin", b"different candidate bytes", "application/octet-stream")})
            assert comparison.status_code == 200
            assert comparison.json()["status"] == "TAMPERED"
            assert comparison.json()["merkle_proof_valid"] is True
            assert comparison.json()["blockchain_status"] == "ANCHORED"
            assert comparison.json()["root_matches"] is True
            tampered = client.post("/api/simulations", headers=headers,
                                   json={"evidence_id": evidence["id"], "scenario": "single_byte"}).json()
            assert tampered["verification_result"] == "TAMPERED"
            assert tampered["original_preserved"] is True
            assert tampered["recomputed_merkle_root"] != batch["merkle_root"]
            report = client.get(f"/api/reports/cases/{case['id']}.pdf", headers=headers)
            assert report.status_code == 200 and report.content.startswith(b"%PDF")
    finally:
        app.dependency_overrides.clear()
    assert benchmark["individual"]["receipts"][0]["transaction_hash"]
