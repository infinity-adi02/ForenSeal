from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from web3 import Web3

from ..auth import current_user, hash_password, require_roles
from ..database import get_db
from ..models import User
from ..services.audit_service import append_audit
from ..services.blockchain_service import BlockchainUnavailable, authorize_wallet

router = APIRouter(prefix="/api/users", tags=["user and role management"])
ROLES = {"administrator", "collector", "investigator", "auditor"}


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern="^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern="^(administrator|collector|investigator|auditor)$")
    wallet_address: str | None = Field(default=None, max_length=42)


class RoleUpdate(BaseModel):
    role: str = Field(pattern="^(administrator|collector|investigator|auditor)$")


@router.get("")
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_roles("administrator"))):
    return [{"id": u.id, "username": u.username, "role": u.role, "wallet_address": u.wallet_address, "created_at": u.created_at}
            for u in db.query(User).order_by(User.created_at).all()]


@router.post("", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db), admin: User = Depends(require_roles("administrator"))):
    wallet = body.wallet_address
    if wallet and not Web3.is_address(wallet):
        raise HTTPException(status_code=422, detail="Wallet address is not a valid EVM address")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role,
                wallet_address=Web3.to_checksum_address(wallet) if wallet else None)
    db.add(user)
    wallet_authorized = False
    wallet_tx = None
    try:
        db.flush()
        if user.wallet_address:
            try:
                wallet_tx = authorize_wallet(user.wallet_address)
                wallet_authorized = True
            except (BlockchainUnavailable, OSError, ValueError, TimeoutError):
                pass
        append_audit(db, actor_id=admin.id, action="USER_CREATED", outcome="SUCCESS", reference=f"{user.username}:{user.role}")
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists") from None
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role,
            "wallet_address": user.wallet_address, "wallet_authorized_on_chain": wallet_authorized,
            "wallet_authorization_tx": wallet_tx, "created_at": user.created_at}


@router.patch("/{user_id}/role")
def update_role(user_id: str, body: RoleUpdate, db: Session = Depends(get_db), admin: User = Depends(require_roles("administrator"))):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "administrator" and body.role != "administrator":
        admin_count = db.query(User).filter(User.role == "administrator").count()
        if admin_count <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last administrator")
    previous_role = user.role
    user.role = body.role
    append_audit(db, actor_id=admin.id, action="USER_ROLE_UPDATED", outcome="SUCCESS",
                 reference=f"{user.username}:{previous_role}->{body.role}")
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role, "wallet_address": user.wallet_address}
