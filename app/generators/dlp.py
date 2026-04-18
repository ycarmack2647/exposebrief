"""Mock Microsoft Purview DLP alert generator."""
from __future__ import annotations

import random as _random
import uuid
from datetime import datetime, timedelta, timezone

from faker import Faker

# SystemRandom avoids cross-generator RNG state collisions that were
# concentrating all synthetic events on a single user during /simulate.
random = _random.SystemRandom()
fake = Faker()

DLP_OPERATIONS = [
    ("FileDownloaded", ["T1530"]),
    ("EmailSent", ["T1048"]),
    ("FileUploaded", ["T1567.002"]),
    ("FileCopiedToRemovableMedia", ["T1052.001"]),
    ("BulkDownload", ["T1530", "T1020"]),
    ("PrintedSensitiveDocument", ["T1005"]),
]

LABELS = ["Public", "Low Sensitivity", "Medium Sensitivity", "High Sensitivity"]
SEVERITIES = ["low", "medium", "high", "critical"]
DESTINATIONS = [
    "personal-gmail.com",
    "dropbox.com",
    "wetransfer.com",
    "usb-drive",
    "internal-sharepoint",
    "external-partner.com",
]
POLICIES = [
    "Employee PII (EDM)",
    "PCI Data",
    "HR Records",
    "SCADA/OT Documentation",
    "Bulk Exfiltration Catch-All",
]


def _pick_severity(label: str, operation: str) -> str:
    if label == "High Sensitivity" or operation == "BulkDownload":
        return random.choices(SEVERITIES, weights=[5, 15, 50, 30])[0]
    if label == "Medium Sensitivity":
        return random.choices(SEVERITIES, weights=[10, 50, 30, 10])[0]
    return random.choices(SEVERITIES, weights=[50, 35, 12, 3])[0]


def generate_one(user_pool: list[str]) -> dict:
    operation, techniques = random.choice(DLP_OPERATIONS)
    label = random.choices(LABELS, weights=[20, 30, 35, 15])[0]
    severity = _pick_severity(label, operation)
    size_mb = round(random.uniform(0.1, 2500.0), 2) if operation == "BulkDownload" else round(random.uniform(0.05, 50.0), 2)

    return {
        "AlertId": f"dlp-{uuid.uuid4().hex}",
        "CreationTime": datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 4320)),
        "UserPrincipalName": random.choice(user_pool),
        "Operation": operation,
        "SensitivityLabel": label,
        "FileSizeMB": size_mb,
        "Destination": random.choice(DESTINATIONS),
        "IsSanctioned": random.choice(DESTINATIONS).startswith("internal"),
        "Severity": severity,
        "MitreTechniques": techniques,
        "PolicyMatches": random.sample(POLICIES, k=random.randint(1, 2)),
    }


def generate(n: int, user_pool: list[str]) -> list[dict]:
    return [generate_one(user_pool) for _ in range(n)]
