from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import current_user, require_roles
from ..database import get_db
from ..models import Case, Evidence, User
from ..schemas import CaseCreate, CaseOut
from ..services.audit_service import append_audit

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(body: CaseCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "collector", "investigator"))):
    case = Case(**body.model_dump(), created_by=user.id)
    db.add(case)
    try:
        db.flush()
        append_audit(db, actor_id=user.id, action="CASE_CREATED", outcome="SUCCESS", case_id=case.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Case reference already exists") from None
    db.refresh(case)
    return {**case.__dict__, "evidence_count": 0}


@router.get("", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    rows = db.query(Case, func.count(Evidence.id)).outerjoin(Evidence).group_by(Case.id).order_by(Case.created_at.desc()).all()
    return [{**case.__dict__, "evidence_count": count} for case, count in rows]


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: str, db: Session = Depends(get_db), _user: User = Depends(current_user)):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    count = db.query(func.count(Evidence.id)).filter(Evidence.case_id == case.id).scalar() or 0
    return {**case.__dict__, "evidence_count": count}
