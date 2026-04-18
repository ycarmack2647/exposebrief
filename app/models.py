"""
Unified telemetry schema for ExposeBrief.

The RiskEvent model is the normalization target for all upstream data sources
(Microsoft Purview DLP, Information Protection, DSPM for AI). All scoring and
API logic operates on this shape — NOT on raw source payloads.

This separation is the core architectural bet of ExposeBrief: one unified
risk surface, many pluggable telemetry connectors.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field
from sqlmodel import Field as SQLField, SQLModel


Severity = Literal["low", "medium", "high", "critical"]
Source = Literal["dlp", "mip", "dspm_ai"]


# ---------------------------------------------------------------------------
# Core unified event shape (API + storage)
# ---------------------------------------------------------------------------
class RiskEvent(SQLModel, table=True):
    """Normalized event written to storage and returned by the API."""

    event_id: str = SQLField(primary_key=True)
    timestamp: datetime = SQLField(index=True)
    user_upn: str = SQLField(index=True)
    source: str = SQLField(index=True)  # "dlp" | "mip" | "dspm_ai"
    event_type: str
    sensitivity_label: Optional[str] = None
    data_volume_mb: Optional[float] = None
    destination: Optional[str] = None
    is_sanctioned: Optional[bool] = None
    raw_severity: str  # Severity literal
    mitre_techniques: str = ""  # stored as CSV; parsed to list in API layer
    raw_payload: str = ""  # JSON string of original source payload (auditability)


class RiskEventOut(BaseModel):
    """API-facing representation (mitre_techniques exposed as list)."""

    event_id: str
    timestamp: datetime
    user_upn: str
    source: Source
    event_type: str
    sensitivity_label: Optional[str] = None
    data_volume_mb: Optional[float] = None
    destination: Optional[str] = None
    is_sanctioned: Optional[bool] = None
    raw_severity: Severity
    mitre_techniques: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scoring output
# ---------------------------------------------------------------------------
class UserRiskScore(BaseModel):
    user_upn: str
    score: float
    event_count: int
    dominant_source: Source
    has_unsanctioned_ai: bool
    total_volume_mb: float
    top_mitre_techniques: list[str]
    risk_band: Literal["green", "yellow", "orange", "red"]


# ---------------------------------------------------------------------------
# Ingest payloads (raw source-shaped — normalizer handles these)
# ---------------------------------------------------------------------------
class SimulateRequest(BaseModel):
    n: int = Field(default=50, ge=1, le=5000)
    sources: list[Source] = Field(default_factory=lambda: ["dlp", "mip", "dspm_ai"])
