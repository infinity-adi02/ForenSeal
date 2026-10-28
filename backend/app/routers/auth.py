from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from ..auth import create_access_token, current_user, verify_password
from ..database import get_db
from ..models import User
from ..schemas import LoginRequest, TokenOut, UserOut
from ..services.fingerprint_access import fingerprint_access_granted

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.post("/login", response_model=TokenOut)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": create_access_token(user), "user": user}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/fingerprint-access")
def unlock_fingerprints(x_fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                        _user: User = Depends(current_user)):
    if not fingerprint_access_granted(x_fingerprint_code):
        raise HTTPException(status_code=403, detail="Admin code is incorrect")
    return {"authorized": True}
