"""Pytest suite for ExposeBrief."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app import storage
from app.models import RiskEventOut
from app.normalizer import normalize
from app.scoring import (
    HIGH_VOLUME_THRESHOLD_MB,
    LABEL_DOWNGRADE_MULTIPLIER,
    UNSANCTIONED_AI_MULTIPLIER,
    risk_band,
    score_user,
)


@pytest.fixture(autouse=True)
def _clean_db():
    storage.init_db()
    storage.clear_all()
    yield
    storage.clear_all()


# ---------------------------------------------------------------------------
# Normalizer tests — round-trip each source shape
# ---------------------------------------------------------------------------
def test_normalize_dlp_minimum_fields():
    payload = {
        "UserPrincipalName": "[email protected]",
        "Operation": "BulkDownload",
        "SensitivityLabel": "High Sensitivity",
        "FileSizeMB": 1500.0,
        "Severity": "critical",
        "MitreTechniques": ["T1530", "T1020"],
    }
    ev = normalize("dlp", payload)
    assert ev.source == "dlp"
    assert ev.user_upn == "[email protected]"
    assert ev.raw_severity == "critical"
    assert "T1530" in ev.mitre_techniques


def test_normalize_mip_downgrade_flagged_high_severity():
    payload = {
        "UserId": "[email protected]",
        "LabelAction": "Downgraded",
        "OldLabel": "High Sensitivity",
        "NewLabel": "Low Sensitivity",
    }
    ev = normalize("mip", payload)
    assert ev.event_type == "label_downgrade"
    assert ev.raw_severity == "high"


def test_normalize_dspm_ai_unsanctioned_sensitive_is_critical_at_volume():
    payload = {
        "User": "[email protected]",
        "AppName": "DeepSeek",
        "IsSanctioned": False,
        "ContainsSensitiveData": True,
        "EgressVolumeMB": 250.0,
        "PromptCount": 75,
    }
    ev = normalize("dspm_ai", payload)
    assert ev.raw_severity == "critical"
    assert "T1567.002" in ev.mitre_techniques
    assert "T1020" in ev.mitre_techniques  # triggered by PromptCount > 50


def test_normalize_unknown_source_raises():
    with pytest.raises(ValueError):
        normalize("nonsense", {})


# ---------------------------------------------------------------------------
# Scoring tests — each multiplier in isolation
# ---------------------------------------------------------------------------
def _ev(source, severity, **kw) -> RiskEventOut:
    return RiskEventOut(
        event_id=kw.get("event_id", f"{source}-x"),
        timestamp=datetime.now(timezone.utc),
        user_upn=kw.get("user_upn", "[email protected]"),
        source=source,
        event_type=kw.get("event_type", "test"),
        raw_severity=severity,
        data_volume_mb=kw.get("data_volume_mb"),
        is_sanctioned=kw.get("is_sanctioned"),
        mitre_techniques=kw.get("mitre_techniques", []),
        destination=kw.get("destination"),
        sensitivity_label=kw.get("sensitivity_label"),
    )


def test_unsanctioned_ai_multiplier_applied():
    events = [_ev("dspm_ai", "high", is_sanctioned=False)]
    score_with = score_user("u@t", events).score

    events_sanctioned = [_ev("dspm_ai", "high", is_sanctioned=True)]
    score_without = score_user("u@t", events_sanctioned).score

    assert pytest.approx(score_with / score_without, rel=0.01) == UNSANCTIONED_AI_MULTIPLIER


def test_label_downgrade_multiplier_applied():
    events_down = [_ev("mip", "high", event_type="label_downgrade")]
    score_down = score_user("u@t", events_down).score

    events_normal = [_ev("mip", "high", event_type="label_applied")]
    score_normal = score_user("u@t", events_normal).score

    assert pytest.approx(score_down / score_normal, rel=0.01) == LABEL_DOWNGRADE_MULTIPLIER


def test_high_volume_multiplier_applied_above_threshold():
    events_high = [_ev("dlp", "medium", data_volume_mb=HIGH_VOLUME_THRESHOLD_MB + 1)]
    events_low = [_ev("dlp", "medium", data_volume_mb=10.0)]
    assert score_user("u", events_high).score > score_user("u", events_low).score


def test_empty_events_return_zero_score():
    s = score_user("nobody@t", [])
    assert s.score == 0.0
    assert s.risk_band == "green"


def test_risk_bands_boundaries():
    assert risk_band(0) == "green"
    assert risk_band(24.99) == "green"
    assert risk_band(25) == "yellow"
    assert risk_band(59.99) == "yellow"
    assert risk_band(60) == "orange"
    assert risk_band(99.99) == "orange"
    assert risk_band(100) == "red"
    assert risk_band(500) == "red"


# ---------------------------------------------------------------------------
# Storage integration
# ---------------------------------------------------------------------------
def test_persist_and_retrieve_round_trip():
    payload = {
        "UserPrincipalName": "[email protected]",
        "Operation": "FileDownloaded",
        "Severity": "high",
    }
    ev = normalize("dlp", payload)
    storage.persist_events([ev])
    results = storage.list_events(user_upn="[email protected]")
    assert len(results) == 1
    assert results[0].source == "dlp"
    assert results[0].raw_severity == "high"
