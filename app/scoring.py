"""
Risk scoring engine.

Scoring philosophy:
  base_score = sum over events of (severity_weight * source_weight)
  final_score = base_score * product(multipliers)

All weights are tunable and exposed via /config endpoint so reviewers and
hiring managers can see the scoring logic without reading source.

Weighting reflects the ExposeBrief thesis that unsanctioned AI egress is the
highest-leverage risk signal in modern enterprises — DSPM for AI carries the
heaviest source weight.
"""
from __future__ import annotations

from collections import Counter
from typing import Literal

from app.models import RiskEventOut, UserRiskScore

# ---------------------------------------------------------------------------
# Tunable configuration
# ---------------------------------------------------------------------------
SOURCE_WEIGHTS: dict[str, float] = {
    "dlp": 0.35,
    "mip": 0.20,
    "dspm_ai": 0.45,  # Shadow AI weighted highest — ExposeBrief thesis
}

SEVERITY_WEIGHTS: dict[str, int] = {
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 10,
}

# Contextual multipliers applied to the base score
UNSANCTIONED_AI_MULTIPLIER = 1.5  # any unsanctioned AI egress
HIGH_VOLUME_MULTIPLIER = 1.3      # aggregate volume > threshold
HIGH_VOLUME_THRESHOLD_MB = 1000.0
LABEL_DOWNGRADE_MULTIPLIER = 1.4  # any label downgrade event

# Risk banding thresholds (applied to final score)
BAND_THRESHOLDS = [
    (25.0, "green"),
    (60.0, "yellow"),
    (100.0, "orange"),
]
# Above 100 => red


def risk_band(score: float) -> Literal["green", "yellow", "orange", "red"]:
    for threshold, band in BAND_THRESHOLDS:
        if score < threshold:
            return band  # type: ignore[return-value]
    return "red"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _base_score(events: list[RiskEventOut]) -> float:
    return sum(
        SEVERITY_WEIGHTS.get(e.raw_severity, 1) * SOURCE_WEIGHTS.get(e.source, 0.1)
        for e in events
    )


def score_user(user_upn: str, events: list[RiskEventOut]) -> UserRiskScore:
    """Compute a composite risk score for a single user from their events."""
    if not events:
        return UserRiskScore(
            user_upn=user_upn,
            score=0.0,
            event_count=0,
            dominant_source="dlp",
            has_unsanctioned_ai=False,
            total_volume_mb=0.0,
            top_mitre_techniques=[],
            risk_band="green",
        )

    base = _base_score(events)

    has_unsanctioned_ai = any(
        e.source == "dspm_ai" and e.is_sanctioned is False for e in events
    )
    total_volume = sum(e.data_volume_mb or 0.0 for e in events)
    has_label_downgrade = any(e.event_type == "label_downgrade" for e in events)

    multiplier = 1.0
    if has_unsanctioned_ai:
        multiplier *= UNSANCTIONED_AI_MULTIPLIER
    if total_volume > HIGH_VOLUME_THRESHOLD_MB:
        multiplier *= HIGH_VOLUME_MULTIPLIER
    if has_label_downgrade:
        multiplier *= LABEL_DOWNGRADE_MULTIPLIER

    final = round(base * multiplier, 2)

    # Aggregates
    source_counts = Counter(e.source for e in events)
    dominant_source = source_counts.most_common(1)[0][0]

    technique_counter: Counter[str] = Counter()
    for e in events:
        technique_counter.update(e.mitre_techniques)
    top_techniques = [t for t, _ in technique_counter.most_common(5)]

    return UserRiskScore(
        user_upn=user_upn,
        score=final,
        event_count=len(events),
        dominant_source=dominant_source,  # type: ignore[arg-type]
        has_unsanctioned_ai=has_unsanctioned_ai,
        total_volume_mb=round(total_volume, 2),
        top_mitre_techniques=top_techniques,
        risk_band=risk_band(final),
    )


def score_all_users(events: list[RiskEventOut]) -> list[UserRiskScore]:
    by_user: dict[str, list[RiskEventOut]] = {}
    for e in events:
        by_user.setdefault(e.user_upn, []).append(e)
    scores = [score_user(upn, evs) for upn, evs in by_user.items()]
    scores.sort(key=lambda s: s.score, reverse=True)
    return scores


def scoring_config() -> dict:
    """Expose the full scoring configuration for transparency."""
    return {
        "source_weights": SOURCE_WEIGHTS,
        "severity_weights": SEVERITY_WEIGHTS,
        "multipliers": {
            "unsanctioned_ai": UNSANCTIONED_AI_MULTIPLIER,
            "high_volume": HIGH_VOLUME_MULTIPLIER,
            "high_volume_threshold_mb": HIGH_VOLUME_THRESHOLD_MB,
            "label_downgrade": LABEL_DOWNGRADE_MULTIPLIER,
        },
        "bands": {
            "green": "< 25",
            "yellow": "25–60",
            "orange": "60–100",
            "red": ">= 100",
        },
    }
