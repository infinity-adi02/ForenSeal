from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import current_user
from ..database import get_db
from ..models import Case, User
from ..services.audit_service import append_audit
from ..services.report_service import generate_report
from ..services.fingerprint_access import fingerprint_access_granted

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/cases/{case_id}.pdf")
def case_report(case_id: str, db: Session = Depends(get_db),
                fingerprint_code: str | None = Header(default=None, alias="X-Fingerprint-Code"),
                user: User = Depends(current_user)):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    pdf, report_id = generate_report(db, case, include_fingerprints=fingerprint_access_granted(fingerprint_code))
    append_audit(db, actor_id=user.id, action="PDF_REPORT_GENERATED", outcome="SUCCESS", case_id=case.id, reference=report_id)
    db.commit()
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="forenseal-{case.reference}.pdf"', "X-Report-ID": report_id})
