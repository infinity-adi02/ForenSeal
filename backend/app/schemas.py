from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    wallet_address: str | None = None
    model_config = ConfigDict(from_attributes=True)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    reference: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=4000)


class CaseOut(BaseModel):
    id: str
    name: str
    reference: str
    description: str
    created_at: datetime
    evidence_count: int = 0


class EvidenceOut(BaseModel):
    id: str
    case_id: str
    original_filename: str
    size_bytes: int
    mime_type: str
    original_sha256: str | None = None
    source_id: str = "user_upload"
    source_name: str = "Unspecified local file"
    source_url: str | None = None
    source_scenario: str | None = None
    collector_id: str
    status: str
    created_at: datetime
    batch_id: str | None
    model_config = ConfigDict(from_attributes=True)


class VerificationOut(BaseModel):
    evidence_id: str
    original_hash: str | None
    current_hash: str | None
    hash_match: bool
    status: str
    verified_at: datetime
    message: str
    merkle_proof_valid: bool | None = None
    anchored_root: str | None = None
    root_matches: bool | None = None
    blockchain_status: str = "NOT_CHECKED"
    candidate_filename: str | None = None
    candidate_size_bytes: int | None = None


class BatchOut(BaseModel):
    id: str
    case_id: str
    merkle_root: str
    manifest_commitment: str
    evidence_count: int
    status: str
    chain_id: int | None
    contract_address: str | None
    transaction_hash: str | None
    created_at: datetime
    chain_status: str | None = None
    model_config = ConfigDict(from_attributes=True)


class CustodyCreate(BaseModel):
    event_type: str = Field(pattern="^(ACCESS|VERIFICATION|TRANSFER_INITIATED)$")
    recipient: str | None = Field(default=None, max_length=80)
    reason: str = Field(default="", max_length=2000)


class TransferResolution(BaseModel):
    accepted: bool
    acknowledgment: str = Field(min_length=1, max_length=500)


class AuditOut(BaseModel):
    sequence: int
    actor_id: str
    action: str
    case_id: str | None
    evidence_id: str | None
    outcome: str
    reference: str | None
    occurred_at: datetime
    previous_hash: str
    entry_hash: str
    model_config = ConfigDict(from_attributes=True)
