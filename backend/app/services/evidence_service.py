import hashlib
import os
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile

from .hashing_service import CHUNK_SIZE


async def persist_upload(upload: UploadFile, storage_dir: Path, max_bytes: int) -> dict:
    """Stream one upload to an exclusive server-generated storage object."""
    storage_dir.mkdir(parents=True, exist_ok=True)
    storage_key = f"{uuid.uuid4().hex}.evidence"
    destination = storage_dir / storage_key
    digest = hashlib.sha256()
    total = 0
    try:
        with destination.open("xb") as output:
            while chunk := await upload.read(CHUNK_SIZE):
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail=f"File exceeds {max_bytes} byte limit")
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()
    return {"storage_key": storage_key, "size_bytes": total, "sha256": digest.hexdigest(),
            "filename": os.path.basename((upload.filename or "evidence.bin").replace("\\", "/"))[:255],
            "mime_type": (upload.content_type or "application/octet-stream")[:150]}
