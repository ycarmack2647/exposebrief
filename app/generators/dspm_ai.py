"""
Mock DSPM-for-AI / Shadow AI egress telemetry generator.

Seeded with the OfficeAI honeypot findings: 103+ unsanctioned AI applications
observed with ~220GB aggregate exfiltration signal. Hero demo data.
"""
from __future__ import annotations

import json
import random as _random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random = _random.SystemRandom()

SEED_FILE = Path("data/seed_shadow_ai.json")


def _load_seed_apps() -> list[dict]:
    if not SEED_FILE.exists():
        return _default_apps()
    try:
        return json.loads(SEED_FILE.read_text())
    except Exception:
        return _default_apps()


def _default_apps() -> list[dict]:
    """Fallback if seed file missing — mirrors structure expected in seed JSON."""
    return [
        {"name": "ChatGPT", "domain": "chat.openai.com", "sanctioned": True, "weight": 15},
        {"name": "Microsoft Copilot", "domain": "copilot.microsoft.com", "sanctioned": True, "weight": 20},
        {"name": "DeepSeek", "domain": "chat.deepseek.com", "sanctioned": False, "weight": 8, "risk_flag": "foreign_ai_platform"},
        {"name": "Character.AI", "domain": "character.ai", "sanctioned": False, "weight": 5},
        {"name": "Claude (personal)", "domain": "claude.ai", "sanctioned": False, "weight": 10},
        {"name": "Gemini (personal)", "domain": "gemini.google.com", "sanctioned": False, "weight": 6},
        {"name": "Perplexity", "domain": "perplexity.ai", "sanctioned": False, "weight": 4},
        {"name": "HuggingChat", "domain": "huggingface.co/chat", "sanctioned": False, "weight": 3},
        {"name": "Poe", "domain": "poe.com", "sanctioned": False, "weight": 3},
        {"name": "You.com", "domain": "you.com", "sanctioned": False, "weight": 2},
        {"name": "Pi", "domain": "pi.ai", "sanctioned": False, "weight": 2},
        {"name": "Mistral Chat", "domain": "chat.mistral.ai", "sanctioned": False, "weight": 2},
    ]


def generate_one(user_pool: list[str], apps: list[dict]) -> dict:
    app = random.choices(apps, weights=[a.get("weight", 1) for a in apps])[0]
    is_sanctioned = app.get("sanctioned", False)

    # Unsanctioned apps skew toward higher volume and more sensitive content
    if not is_sanctioned:
        volume = round(random.uniform(5.0, 500.0), 2)
        contains_sensitive = random.random() < 0.55
        prompt_count = random.randint(5, 300)
    else:
        volume = round(random.uniform(0.1, 50.0), 2)
        contains_sensitive = random.random() < 0.15
        prompt_count = random.randint(1, 80)

    return {
        "SignalId": f"dspm-{uuid.uuid4().hex}",
        "DetectedAt": datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 4320)),
        "User": random.choice(user_pool),
        "AppName": app["name"],
        "AppDomain": app["domain"],
        "IsSanctioned": is_sanctioned,
        "EgressVolumeMB": volume,
        "PromptCount": prompt_count,
        "ContainsSensitiveData": contains_sensitive,
        "SensitivityLabel": random.choice(["High Sensitivity", "Medium Sensitivity", None]) if contains_sensitive else None,
        "RiskFlag": app.get("risk_flag"),
    }


def generate(n: int, user_pool: list[str]) -> list[dict]:
    apps = _load_seed_apps()
    return [generate_one(user_pool, apps) for _ in range(n)]
