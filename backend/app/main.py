from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from .auth import hash_password
from .config import settings
from .database import Base, SessionLocal, engine, migrate_early_development_schema
from .models import User
from .routers import audit, auth, batches, benchmarks, cases, custody, datasets, evidence, reports, search, simulator, users


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate_early_development_schema()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == settings.bootstrap_admin_username))
        if admin is None:
            db.add(User(username=settings.bootstrap_admin_username, password_hash=hash_password(settings.bootstrap_admin_password), role="administrator"))
            db.commit()
    yield


app = FastAPI(title="ForenSeal API", version="0.1.0", description="ForenSeal digital evidence integrity and custody ledger.", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(datasets.router)
app.include_router(search.router)
app.include_router(audit.router)
app.include_router(batches.router)
app.include_router(custody.router)
app.include_router(simulator.router)
app.include_router(reports.router)
app.include_router(benchmarks.router)
app.include_router(users.router)


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok", "service": "forenseal-api", "blockchain": "not_configured"}
