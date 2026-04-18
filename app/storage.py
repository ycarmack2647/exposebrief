"""SQLite storage layer. Keeps persistence concerns out of the API."""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Optional

from sqlmodel import Session, SQLModel, create_engine, select

from app.models import RiskEvent, RiskEventOut

DB_PATH = Path("data/exposebrief.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    SQLModel.metadata.create_all(_engine)


@contextmanager
def get_session():
    session = Session(_engine)
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------
def persist_events(events: Iterable[RiskEvent]) -> int:
    count = 0
    with get_session() as session:
        for ev in events:
            session.merge(ev)  # idempotent upsert on event_id
            count += 1
        session.commit()
    return count


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------
def _to_out(ev: RiskEvent) -> RiskEventOut:
    return RiskEventOut(
        event_id=ev.event_id,
        timestamp=ev.timestamp,
        user_upn=ev.user_upn,
        source=ev.source,  # type: ignore[arg-type]
        event_type=ev.event_type,
        sensitivity_label=ev.sensitivity_label,
        data_volume_mb=ev.data_volume_mb,
        destination=ev.destination,
        is_sanctioned=ev.is_sanctioned,
        raw_severity=ev.raw_severity,  # type: ignore[arg-type]
        mitre_techniques=[t for t in ev.mitre_techniques.split(",") if t],
    )


def list_events(
    user_upn: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 500,
) -> list[RiskEventOut]:
    with get_session() as session:
        stmt = select(RiskEvent).order_by(RiskEvent.timestamp.desc()).limit(limit)
        if user_upn:
            stmt = stmt.where(RiskEvent.user_upn == user_upn)
        if source:
            stmt = stmt.where(RiskEvent.source == source)
        if severity:
            stmt = stmt.where(RiskEvent.raw_severity == severity)
        return [_to_out(e) for e in session.exec(stmt).all()]


def all_events() -> list[RiskEventOut]:
    return list_events(limit=100_000)


def count_events() -> int:
    with get_session() as session:
        return len(session.exec(select(RiskEvent.event_id)).all())


def clear_all() -> None:
    """Used by tests only."""
    with get_session() as session:
        for ev in session.exec(select(RiskEvent)).all():
            session.delete(ev)
        session.commit()


def serialize_payload(payload: dict) -> str:
    return json.dumps(payload, default=str)
