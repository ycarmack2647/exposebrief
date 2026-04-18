"""
ExposeBrief FastAPI application.

Endpoints:
  GET  /                    — health + version
  GET  /config              — scoring configuration (transparency)
  POST /ingest/{source}     — ingest raw source payload (dlp | mip | dspm_ai)
  POST /simulate            — generate N events across sources (demo button)
  GET  /events              — list events (filters: user_upn, source, severity)
  GET  /risk/top            — top-N risky users
  GET  /risk/user/{upn}     — full risk breakdown for one user
  GET  /stats               — aggregate dashboard stats
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app import storage
from app.generators import dlp as dlp_gen
from app.generators import dspm_ai as dspm_gen
from app.generators import mip as mip_gen
from app.models import RiskEventOut, SimulateRequest, UserRiskScore
from app.normalizer import normalize
from app.scoring import score_all_users, score_user, scoring_config

app = FastAPI(
    title="ExposeBrief",
    description=(
        "Reference architecture that normalizes DLP, Information Protection, "
        "and AI telemetry into a unified risk-scoring system."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Synthetic user pool used by /simulate.
# Built programmatically to guarantee 12 distinct string objects.
_USER_NAMES = [
    "jane.doe", "mike.smith", "carlos.rivera", "aisha.patel",
    "ravi.kumar", "sarah.lee", "jamal.turner", "priya.nair",
    "kevin.obrien", "nina.ivanova", "tomas.becker", "hana.saito",
]
USER_POOL = [f"{name}@contoso.example" for name in _USER_NAMES]


@app.on_event("startup")
def _startup() -> None:
    storage.init_db()


# ---------------------------------------------------------------------------
# Health + config
# ---------------------------------------------------------------------------
@app.get("/")
def root() -> dict:
    return {
        "service": "ExposeBrief",
        "version": "0.1.0",
        "docs": "/docs",
        "event_count": storage.count_events(),
    }


@app.get("/config")
def get_config() -> dict:
    return scoring_config()


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
@app.post("/ingest/{source}")
def ingest(source: str, payload: dict) -> dict:
    if source not in ("dlp", "mip", "dspm_ai"):
        raise HTTPException(400, f"Unknown source: {source}")
    try:
        event = normalize(source, payload)
    except KeyError as e:
        raise HTTPException(400, f"Missing required field: {e}")
    storage.persist_events([event])
    return {"event_id": event.event_id, "source": source, "status": "ingested"}


@app.post("/simulate")
def simulate(req: SimulateRequest) -> dict:
    events = []
    per_source = max(1, req.n // len(req.sources))

    if "dlp" in req.sources:
        payloads = dlp_gen.generate(per_source, USER_POOL)
        events.extend(normalize("dlp", p) for p in payloads)
    if "mip" in req.sources:
        payloads = mip_gen.generate(per_source, USER_POOL)
        events.extend(normalize("mip", p) for p in payloads)
    if "dspm_ai" in req.sources:
        payloads = dspm_gen.generate(per_source, USER_POOL)
        events.extend(normalize("dspm_ai", p) for p in payloads)

    persisted = storage.persist_events(events)
    return {"generated": persisted, "sources": req.sources}


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------
@app.get("/events", response_model=list[RiskEventOut])
def get_events(
    user_upn: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=500, ge=1, le=10_000),
) -> list[RiskEventOut]:
    return storage.list_events(user_upn=user_upn, source=source, severity=severity, limit=limit)


@app.get("/risk/top", response_model=list[UserRiskScore])
def get_top_risky_users(limit: int = Query(default=10, ge=1, le=100)) -> list[UserRiskScore]:
    scores = score_all_users(storage.all_events())
    return scores[:limit]


@app.get("/risk/user/{upn}", response_model=UserRiskScore)
def get_user_risk(upn: str) -> UserRiskScore:
    events = storage.list_events(user_upn=upn, limit=10_000)
    return score_user(upn, events)


@app.get("/stats")
def get_stats() -> dict:
    """Aggregate dashboard stats."""
    events = storage.all_events()
    scores = score_all_users(events)

    unsanctioned_ai_events = [e for e in events if e.source == "dspm_ai" and e.is_sanctioned is False]
    unsanctioned_volume = sum(e.data_volume_mb or 0 for e in unsanctioned_ai_events)

    band_counts = {"green": 0, "yellow": 0, "orange": 0, "red": 0}
    for s in scores:
        band_counts[s.risk_band] += 1

    return {
        "total_events": len(events),
        "total_users": len(scores),
        "high_risk_users": sum(1 for s in scores if s.risk_band in ("orange", "red")),
        "unsanctioned_ai_events": len(unsanctioned_ai_events),
        "unsanctioned_ai_volume_mb": round(unsanctioned_volume, 2),
        "avg_risk_score": round(sum(s.score for s in scores) / len(scores), 2) if scores else 0.0,
        "risk_band_distribution": band_counts,
    }
