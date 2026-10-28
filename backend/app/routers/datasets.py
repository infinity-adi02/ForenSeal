from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import current_user
from ..database import get_db
from ..models import Evidence, User
from ..services.dataset_registry import SOURCES

router = APIRouter(prefix="/api/datasets", tags=["datasets"])


@router.get("/sources")
def dataset_sources(db: Session = Depends(get_db), _user: User = Depends(current_user)):
    result = []
    for source in SOURCES.values():
        rows = db.query(Evidence).filter(Evidence.source_id == source["id"]).all()
        result.append({**source,
                       "import_status": "FILES_IMPORTED" if rows else "REFERENCE_ONLY",
                       "imported_file_count": len(rows),
                       "latest_imported_at": max((row.created_at for row in rows), default=None)})
    return result
