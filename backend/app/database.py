from datetime import timezone

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.types import DateTime, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class UTCDateTime(TypeDecorator):
    """SQLite-safe timestamp storage that restores an explicit UTC offset."""
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate_early_development_schema() -> None:
    """Additive migration for databases created by earlier local development runs."""
    inspector = inspect(engine)
    if "users" in inspector.get_table_names() and "wallet_address" not in {c["name"] for c in inspector.get_columns("users")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE users ADD COLUMN wallet_address VARCHAR(42)"))
    if "custody_events" in inspector.get_table_names() and "chain_transfer_id" not in {c["name"] for c in inspector.get_columns("custody_events")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE custody_events ADD COLUMN chain_transfer_id INTEGER"))
    if "evidence" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("evidence")}
        additions = {
            "source_id": "VARCHAR(80) NOT NULL DEFAULT 'user_upload'",
            "source_name": "VARCHAR(160) NOT NULL DEFAULT 'Unspecified local file'",
            "source_url": "VARCHAR(500)",
            "source_scenario": "TEXT",
        }
        with engine.begin() as connection:
            for column, declaration in additions.items():
                if column not in columns:
                    connection.execute(text(f"ALTER TABLE evidence ADD COLUMN {column} {declaration}"))
