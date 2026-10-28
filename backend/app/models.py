import uuid
from datetime import datetime, timezone

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base, UTCDateTime


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="investigator")
    wallet_address: Mapped[str | None] = mapped_column(String(42), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), index=True)
    reference: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="case")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str] = mapped_column(String(150), default="application/octet-stream")
    original_sha256: Mapped[str] = mapped_column(String(64))
    source_id: Mapped[str] = mapped_column(String(80), default="user_upload", index=True)
    source_name: Mapped[str] = mapped_column(String(160), default="Unspecified local file")
    source_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    collector_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(30), default="ORIGINAL")
    batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    case: Mapped[Case] = relationship(back_populates="evidence")


class Batch(Base):
    __tablename__ = "batches"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    merkle_root: Mapped[str] = mapped_column(String(64))
    manifest_commitment: Mapped[str] = mapped_column(String(64))
    evidence_count: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    contract_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transaction_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class CustodyEvent(Base):
    __tablename__ = "custody_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    event_type: Mapped[str] = mapped_column(String(40))
    outcome: Mapped[str] = mapped_column(String(30))
    recipient: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    blockchain_reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    chain_transfer_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class Simulation(Base):
    __tablename__ = "simulations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    scenario: Mapped[str] = mapped_column(String(30))
    working_key: Mapped[str] = mapped_column(String(120))
    modified_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(30))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status: Mapped[str] = mapped_column(String(30))
    result_json: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class AuditAnchor(Base):
    __tablename__ = "audit_anchors"
    through_sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    commitment: Mapped[str] = mapped_column(String(64))
    chain_id: Mapped[int] = mapped_column(Integer)
    contract_address: Mapped[str] = mapped_column(String(64))
    transaction_hash: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_log"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(80))
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    evidence_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(30))
    reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now_utc)
    previous_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)
