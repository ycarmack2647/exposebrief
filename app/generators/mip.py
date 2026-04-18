"""Mock Microsoft Information Protection label event generator."""
from __future__ import annotations

import random as _random
import uuid
from datetime import datetime, timedelta, timezone

random = _random.SystemRandom()

LABELS = ["Public", "Low Sensitivity", "Medium Sensitivity", "High Sensitivity"]
ACTIONS = ["Applied", "Upgraded", "Removed", "Downgraded"]
# Weighted: most events are applications, downgrades are rarer but high-signal
ACTION_WEIGHTS = [55, 15, 10, 20]


def generate_one(user_pool: list[str]) -> dict:
    action = random.choices(ACTIONS, weights=ACTION_WEIGHTS)[0]

    if action == "Downgraded":
        old_label = random.choice(["High Sensitivity", "Medium Sensitivity"])
        new_label = "Low Sensitivity" if old_label == "Medium Sensitivity" else "Medium Sensitivity"
    elif action == "Upgraded":
        old_label = random.choice(["Public", "Low Sensitivity"])
        new_label = random.choice(["Medium Sensitivity", "High Sensitivity"])
    elif action == "Applied":
        old_label = None
        new_label = random.choice(LABELS)
    else:  # Removed
        old_label = random.choice(LABELS)
        new_label = None

    return {
        "EventId": f"mip-{uuid.uuid4().hex}",
        "TimeGenerated": datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 4320)),
        "UserId": random.choice(user_pool),
        "LabelAction": action,
        "OldLabel": old_label,
        "NewLabel": new_label,
        "FileSizeMB": round(random.uniform(0.01, 100.0), 2),
        "MitreTechniques": ["T1565.001"] if action == "Downgraded" else [],
    }


def generate(n: int, user_pool: list[str]) -> list[dict]:
    return [generate_one(user_pool) for _ in range(n)]
