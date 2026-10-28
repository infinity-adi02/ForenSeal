import hashlib
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.config import settings
from app.database import Base, get_db
from app.main import app
from app.models import User


def test_app_phase1_upload_verify_and_auth(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(settings, "storage_dir", tmp_path)
    monkeypatch.setattr(settings, "max_upload_bytes", 1024)
    monkeypatch.setattr(settings, "blockchain_rpc_url", "http://127.0.0.1:1")
    monkeypatch.setattr(settings, "fingerprint_reveal_code", "test-admin-code")
    with TestingSession() as db:
        db.add(User(id=str(uuid.uuid4()), username="testadmin", password_hash=hash_password("pass"), role="administrator",
                    wallet_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"))
        db.commit()

    def override_db():
        with TestingSession() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            logged_in = client.post("/api/auth/login", json={"username": "testadmin", "password": "pass"})
            assert logged_in.status_code == 200
            token = logged_in.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            case = client.post("/api/cases", headers=headers, json={"name": "Incident 7", "reference": "INC-7"})
            assert case.status_code == 201
            data = b"case evidence"
            uploaded = client.post(f"/api/cases/{case.json()['id']}/evidence", headers=headers,
                                   files={"file": ("..\\..\\sample.bin", data, "application/octet-stream")})
            assert uploaded.status_code == 201
            assert uploaded.json()["original_filename"] == "sample.bin"
            assert uploaded.json()["original_sha256"] is None
            assert client.get(f"/api/cases/{case.json()['id']}/evidence", headers=headers).json()[0]["original_sha256"] is None
            locked_verify = client.post(f"/api/evidence/{uploaded.json()['id']}/verify", headers=headers).json()
            assert locked_verify["status"] == "VERIFIED"
            assert locked_verify["original_hash"] is None and locked_verify["current_hash"] is None
            assert client.post("/api/auth/fingerprint-access", headers={**headers, "X-Fingerprint-Code": "wrong"}).status_code == 403
            assert client.post("/api/auth/fingerprint-access", headers={**headers, "X-Fingerprint-Code": "test-admin-code"}).status_code == 200
            headers["X-Fingerprint-Code"] = "test-admin-code"
            uploaded = client.get(f"/api/evidence/{uploaded.json()['id']}", headers=headers)
            assert uploaded.status_code == 200
            assert uploaded.json()["original_sha256"] == hashlib.sha256(data).hexdigest()
            candidate_match = client.post(f"/api/evidence/{uploaded.json()['id']}/verify-upload", headers=headers,
                                          files={"file": ("matching-copy.bin", data, "application/octet-stream")})
            assert candidate_match.status_code == 200
            assert candidate_match.json()["status"] == "VERIFIED"
            assert candidate_match.json()["current_hash"] == uploaded.json()["original_sha256"]
            candidate_mismatch = client.post(f"/api/evidence/{uploaded.json()['id']}/verify-upload", headers=headers,
                                             files={"file": ("modified-copy.bin", b"case evidencf", "application/octet-stream")})
            assert candidate_mismatch.status_code == 200
            assert candidate_mismatch.json()["status"] == "TAMPERED"
            assert candidate_mismatch.json()["candidate_filename"] == "modified-copy.bin"
            bots_export = b"timestamp,event\n2024-01-01T00:00:00Z,synthetic-bots-fixture\n"
            bots = client.post(f"/api/cases/{case.json()['id']}/evidence", headers=headers,
                               data={"source_id": "botsv3"},
                               files={"file": ("selected-events.csv", bots_export, "text/csv")})
            assert bots.status_code == 201
            assert bots.json()["source_name"] == "Splunk BOTS v3"
            assert bots.json()["source_url"] == "https://github.com/splunk/botsv3"
            assert bots.json()["original_sha256"] == hashlib.sha256(bots_export).hexdigest()
            assert bots.json()["source_scenario"] is None
            otrf_export = b'{"fixture":"synthetic","event":"process-start"}\n'
            otrf = client.post(f"/api/cases/{case.json()['id']}/evidence", headers=headers,
                               data={"source_id": "otrf", "source_scenario": "synthetic test scenario"},
                               files={"file": ("scenario.jsonl", otrf_export, "application/jsonl")})
            assert otrf.status_code == 201
            assert otrf.json()["source_name"] == "OTRF Security-Datasets"
            assert otrf.json()["source_scenario"] == "synthetic test scenario"
            assert otrf.json()["original_sha256"] == hashlib.sha256(otrf_export).hexdigest()
            sources = {item["id"]: item for item in client.get("/api/datasets/sources", headers=headers).json()}
            assert sources["botsv3"]["import_status"] == "FILES_IMPORTED"
            assert sources["botsv3"]["imported_file_count"] == 1
            assert sources["ethereum_bigquery"]["import_status"] == "REFERENCE_ONLY"
            fuzzy_cases = client.get("/api/search", headers=headers, params={"q": "Incidnt 7"}).json()["results"]
            assert any(item["kind"] == "Case" and item["title"] == "Incident 7" for item in fuzzy_cases)
            evidence_hits = client.get("/api/search", headers=headers, params={"q": "sample.bin"}).json()["results"]
            assert any(item["kind"] == "Evidence" and item["title"] == "sample.bin" for item in evidence_hits)
            assert client.post(f"/api/cases/{case.json()['id']}/evidence", headers=headers,
                               data={"source_id": "invented-source"},
                               files={"file": ("bad.bin", b"x", "application/octet-stream")}).status_code == 422
            evidence_id = uploaded.json()["id"]
            too_large = client.post(f"/api/cases/{case.json()['id']}/evidence", headers=headers,
                                    files={"file": ("oversize.bin", b"x" * 1025, "application/octet-stream")})
            assert too_large.status_code == 413
            assert client.post(f"/api/evidence/{evidence_id}/verify", headers=headers).json()["status"] == "VERIFIED"
            batch = client.post(f"/api/cases/{case.json()['id']}/batches", headers=headers)
            assert batch.status_code == 201
            assert batch.json()["merkle_root"]
            assert batch.json()["status"] == "PENDING"  # no local EVM is running in this test
            comparison_with_batch = client.post(f"/api/evidence/{evidence_id}/verify-upload", headers=headers,
                                                files={"file": ("modified-copy.bin", b"case evidencf", "application/octet-stream")})
            assert comparison_with_batch.status_code == 200
            assert comparison_with_batch.json()["status"] == "TAMPERED"
            assert comparison_with_batch.json()["merkle_proof_valid"] is True
            assert comparison_with_batch.json()["blockchain_status"] == "RPC_UNAVAILABLE"
            simulation = client.post("/api/simulations", headers=headers,
                                     json={"evidence_id": evidence_id, "scenario": "single_byte"})
            assert simulation.status_code == 200
            assert simulation.json()["verification_result"] == "TAMPERED"
            assert simulation.json()["original_preserved"] is True
            custody = client.post(f"/api/evidence/{evidence_id}/custody", headers=headers,
                                  json={"event_type": "ACCESS", "reason": "Initial review"})
            assert custody.status_code == 200
            assert client.get(f"/api/evidence/{evidence_id}/custody", headers=headers).json()[-1]["outcome"] == "RECORDED_OFF_CHAIN"
            transfer = client.post(f"/api/evidence/{evidence_id}/custody", headers=headers,
                                   json={"event_type": "TRANSFER_INITIATED", "recipient": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                                         "reason": "Transfer for review"})
            assert transfer.status_code == 200
            assert transfer.json()["outcome"] == "PENDING_ACKNOWLEDGMENT_OFF_CHAIN"
            resolution = client.post(f"/api/evidence/custody/{transfer.json()['id']}/resolve", headers=headers,
                                     json={"accepted": True, "acknowledgment": "Received for review"})
            assert resolution.status_code == 200
            assert resolution.json()["outcome"] == "ACCEPTED_OFF_CHAIN"
            pdf = client.get(f"/api/reports/cases/{case.json()['id']}.pdf", headers=headers)
            assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
            added_user = client.post("/api/users", headers=headers,
                                     json={"username": "reviewer", "password": "secure-password-2026", "role": "auditor"})
            assert added_user.status_code == 201
            auditor_token = client.post("/api/auth/login", json={"username": "reviewer", "password": "secure-password-2026"}).json()["access_token"]
            forbidden = client.post("/api/cases", headers={"Authorization": f"Bearer {auditor_token}"},
                                    json={"name": "No access", "reference": "NO-ACCESS"})
            assert forbidden.status_code == 403
            assert client.patch(f"/api/users/{logged_in.json()['user']['id']}/role", headers=headers,
                                json={"role": "investigator"}).status_code == 409
            assert client.patch(f"/api/users/{added_user.json()['id']}/role", headers=headers,
                                json={"role": "collector"}).json()["role"] == "collector"
            stored = next(path for path in tmp_path.iterdir() if path.is_file() and path.read_bytes() == data)
            stored.write_bytes(b"case evidencf")
            tampered = client.post(f"/api/evidence/{evidence_id}/verify", headers=headers).json()
            assert tampered["status"] == "TAMPERED"
            assert tampered["current_hash"] != tampered["original_hash"]
            stored.unlink()
            assert client.post(f"/api/evidence/{evidence_id}/verify", headers=headers).json()["status"] == "MISSING"
            assert client.get("/api/audit/verify", headers=headers).json()["valid"] is True
            assert client.get("/api/cases").status_code == 401
    finally:
        app.dependency_overrides.clear()
