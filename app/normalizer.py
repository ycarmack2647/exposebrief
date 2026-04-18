"""
Source-specific normalizers.

Each public function takes a raw source payload (shaped like what you'd actually
receive from Microsoft Graph / Purview activity explorer / DSPM) and returns a
unified RiskEvent. The mapping is intentionally explicit — this module IS the
documentation of ExposeBrief's normalization contract.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.models import RiskEvent
from app.storage import serialize_payload


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _mitre_csv(techniques: list[str]) -> str:
    return ",".join(techniques)


# ---------------------------------------------------------------------------
# Microsoft Purview DLP (Activity Explorer shape)
# ---------------------------------------------------------------------------
def normalize_dlp(payload: dict[str, Any]) -> RiskEvent:
    """
    Maps a Purview DLP alert payload to RiskEvent.

    Expected inbound shape (simplified, based on Activity Explorer export):
      - AlertId, CreationTime, UserPrincipalName
      - Operation (e.g., 'FileDownloaded', 'EmailSent')
      - SensitivityLabel, FileSizeMB, Destination, Severity
      - PolicyMatches (list[str])
    """
    return RiskEvent(
        event_id=payload.get("AlertId") or f"dlp-{uuid.uuid4().hex}",
        timestamp=payload.get("CreationTime") or _now(),
        user_upn=payload["UserPrincipalName"],
        source="dlp",
        event_type=payload.get("Operation", "unknown"),
        sensitivity_label=payload.get("SensitivityLabel"),
        data_volume_mb=payload.get("FileSizeMB"),
        destination=payload.get("Destination"),
        is_sanctioned=payload.get("IsSanctioned"),
        raw_severity=(payload.get("Severity") or "medium").lower(),
        mitre_techniques=_mitre_csv(payload.get("MitreTechniques", [])),
        raw_payload=serialize_payload(payload),
    )


# ---------------------------------------------------------------------------
# Microsoft Information Protection (label events)
# ---------------------------------------------------------------------------
def normalize_mip(payload: dict[str, Any]) -> RiskEvent:
    """
    Maps a MIP label event to RiskEvent.

    Expected inbound shape:
      - EventId, TimeGenerated, UserId
      - LabelAction ('Applied' | 'Downgraded' | 'Removed' | 'Upgraded')
      - OldLabel, NewLabel, FileSizeMB
    """
    action = payload.get("LabelAction", "Applied")
    severity_map = {
        "Applied": "low",
        "Upgraded": "low",
        "Removed": "high",
        "Downgraded": "high",
    }
    event_type_map = {
        "Applied": "label_applied",
        "Upgraded": "label_upgraded",
        "Removed": "label_removed",
        "Downgraded": "label_downgrade",  # matches scoring multiplier key
    }
    return RiskEvent(
        event_id=payload.get("EventId") or f"mip-{uuid.uuid4().hex}",
        timestamp=payload.get("TimeGenerated") or _now(),
        user_upn=payload["UserId"],
        source="mip",
        event_type=event_type_map.get(action, "label_event"),
        sensitivity_label=payload.get("NewLabel") or payload.get("OldLabel"),
        data_volume_mb=payload.get("FileSizeMB"),
        destination=None,
        is_sanctioned=None,
        raw_severity=severity_map.get(action, "medium"),
        mitre_techniques=_mitre_csv(payload.get("MitreTechniques", [])),
        raw_payload=serialize_payload(payload),
    )


# ---------------------------------------------------------------------------
# DSPM for AI / Shadow AI egress telemetry
# ---------------------------------------------------------------------------
def normalize_dspm_ai(payload: dict[str, Any]) -> RiskEvent:
    """
    Maps a DSPM-for-AI / Shadow AI egress signal to RiskEvent.

    Expected inbound shape:
      - SignalId, DetectedAt, User
      - AppName, AppDomain, IsSanctioned
      - EgressVolumeMB, PromptCount, ContainsSensitiveData
    """
    is_sanctioned = payload.get("IsSanctioned", False)
    contains_sensitive = payload.get("ContainsSensitiveData", False)
    volume = payload.get("EgressVolumeMB", 0.0)

    # Severity derivation: unsanctioned + sensitive + volume
    if not is_sanctioned and contains_sensitive and volume > 100:
        severity = "critical"
    elif not is_sanctioned and contains_sensitive:
        severity = "high"
    elif not is_sanctioned:
        severity = "medium"
    else:
        severity = "low"

    techniques = ["T1567.002"]  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
    if payload.get("PromptCount", 0) > 50:
        techniques.append("T1020")  # Automated Exfiltration

    return RiskEvent(
        event_id=payload.get("SignalId") or f"dspm-{uuid.uuid4().hex}",
        timestamp=payload.get("DetectedAt") or _now(),
        user_upn=payload["User"],
        source="dspm_ai",
        event_type="shadow_ai_egress" if not is_sanctioned else "sanctioned_ai_use",
        sensitivity_label=payload.get("SensitivityLabel"),
        data_volume_mb=volume,
        destination=payload.get("AppName") or payload.get("AppDomain"),
        is_sanctioned=is_sanctioned,
        raw_severity=severity,
        mitre_techniques=_mitre_csv(techniques),
        raw_payload=serialize_payload(payload),
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
NORMALIZERS = {
    "dlp": normalize_dlp,
    "mip": normalize_mip,
    "dspm_ai": normalize_dspm_ai,
}


def normalize(source: str, payload: dict[str, Any]) -> RiskEvent:
    if source not in NORMALIZERS:
        raise ValueError(f"Unknown source: {source}")
    return NORMALIZERS[source](payload)
