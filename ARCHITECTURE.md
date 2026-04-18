# ExposeBrief Architecture

## Core thesis

Enterprise data-security programs run on three broadly separate telemetry streams:

1. **DLP alerts** — user/content violations against DLP policies (Microsoft Purview, Forcepoint, Symantec, etc.)
2. **Information Protection events** — sensitivity label apply / remove / upgrade / downgrade actions
3. **DSPM for AI / Shadow AI telemetry** — egress of enterprise data to sanctioned or unsanctioned AI applications

Each of these lives in its own pane of glass. Each has its own schema, its own severity semantics, its own notion of "risk." The result: **no single authoritative answer to "who is most risky right now?"**

ExposeBrief's architectural bet is that this is solvable by forcing all three streams through a unified normalized schema (`RiskEvent`) before any scoring, storage, or presentation logic runs. Downstream components never see source-specific payloads.

---

## Component diagram

```
┌─────────────────────┐    ┌──────────────────────┐
│ Purview DLP         │───▶│                      │
│ (Activity Explorer) │    │                      │
└─────────────────────┘    │                      │
                           │                      │    ┌──────────┐
┌─────────────────────┐    │   Normalizer         │───▶│ SQLite   │
│ MIP Label Events    │───▶│   (app/normalizer.py)│    └──────────┘
│ (Audit Logs)        │    │                      │          │
└─────────────────────┘    │                      │          ▼
                           │                      │    ┌──────────────┐
┌─────────────────────┐    │                      │    │ Scoring      │
│ DSPM for AI         │───▶│                      │    │ Engine       │
│ (Egress telemetry)  │    └──────────────────────┘    └──────────────┘
└─────────────────────┘               │                       │
                                      ▼                       ▼
                           ┌─────────────────────────────────────┐
                           │  FastAPI  (app/main.py)              │
                           │  /events  /risk/top  /stats  /config │
                           └─────────────────────────────────────┘
                                      │            │
                                      ▼            ▼
                           ┌──────────────┐  ┌─────────────────┐
                           │ Streamlit UI │  │ External        │
                           │ (dashboard/) │  │ consumers:      │
                           └──────────────┘  │  Splunk HEC     │
                                             │  Power BI       │
                                             │  Sentinel       │
                                             └─────────────────┘
```

---

## The RiskEvent schema

Every upstream signal lands in this shape. This is the contract.

| Field | Type | Purpose |
|---|---|---|
| `event_id` | str (PK) | Stable identifier, used for idempotent upserts |
| `timestamp` | datetime | When the event occurred (source-provided) |
| `user_upn` | str | Actor (email / UPN) |
| `source` | `dlp` \| `mip` \| `dspm_ai` | Provenance — used in scoring weights |
| `event_type` | str | Action taken (e.g., `bulk_download`, `label_downgrade`, `shadow_ai_egress`) |
| `sensitivity_label` | str? | Associated Microsoft Purview label if any |
| `data_volume_mb` | float? | Volume of data in play — drives aggregate-volume multiplier |
| `destination` | str? | Where data went (domain, app name, device) |
| `is_sanctioned` | bool? | Whether the destination is sanctioned — drives unsanctioned-AI multiplier |
| `raw_severity` | low/medium/high/critical | Source-derived severity |
| `mitre_techniques` | list[str] | ATT&CK techniques for hunt-team consumption |
| `raw_payload` | str (JSON) | Original source payload preserved for audit |

---

## Normalization mappings

### 1. Microsoft Purview DLP

Inbound payload shape (based on Activity Explorer export format):

| Source field | Maps to | Notes |
|---|---|---|
| `AlertId` | `event_id` | |
| `CreationTime` | `timestamp` | UTC |
| `UserPrincipalName` | `user_upn` | |
| `Operation` | `event_type` | e.g., `FileDownloaded`, `BulkDownload` |
| `SensitivityLabel` | `sensitivity_label` | |
| `FileSizeMB` | `data_volume_mb` | |
| `Destination` | `destination` | |
| `Severity` | `raw_severity` | lowercased |
| `MitreTechniques` | `mitre_techniques` | CSV-stored |
| *(constant)* | `source` | `"dlp"` |

### 2. Microsoft Information Protection (label events)

| Source field | Maps to | Notes |
|---|---|---|
| `EventId` | `event_id` | |
| `TimeGenerated` | `timestamp` | |
| `UserId` | `user_upn` | |
| `LabelAction` | `event_type` | `Downgraded` → `label_downgrade` (scoring-relevant) |
| `NewLabel` / `OldLabel` | `sensitivity_label` | |
| `FileSizeMB` | `data_volume_mb` | |
| *(derived from action)* | `raw_severity` | Downgraded/Removed → `high`; Applied/Upgraded → `low` |
| *(constant)* | `source` | `"mip"` |

**Severity derivation rationale:** A label *downgrade* is an explicit trust-reducing action — often the first signal of intent to exfiltrate — so it is flagged `high` regardless of label involved.

### 3. DSPM for AI / Shadow AI

| Source field | Maps to | Notes |
|---|---|---|
| `SignalId` | `event_id` | |
| `DetectedAt` | `timestamp` | |
| `User` | `user_upn` | |
| `AppName` / `AppDomain` | `destination` | |
| `IsSanctioned` | `is_sanctioned` | Drives scoring multiplier |
| `EgressVolumeMB` | `data_volume_mb` | |
| *(derived)* | `event_type` | `shadow_ai_egress` if unsanctioned else `sanctioned_ai_use` |
| *(derived)* | `raw_severity` | See table below |
| *(derived)* | `mitre_techniques` | Always `T1567.002`; adds `T1020` if PromptCount > 50 |
| *(constant)* | `source` | `"dspm_ai"` |

**Severity derivation matrix:**

| Sanctioned? | Contains sensitive data? | Volume | Severity |
|---|---|---|---|
| No | Yes | > 100 MB | `critical` |
| No | Yes | ≤ 100 MB | `high` |
| No | No | — | `medium` |
| Yes | — | — | `low` |

---

## Scoring rationale

### Why DSPM-for-AI is weighted highest (0.45)

Traditional DLP and MIP programs were designed when the threat surface was files leaving the network through known channels (email, USB, upload). Generative AI usage has created a new primary exfiltration surface that most DLP engines don't natively classify. ExposeBrief treats Shadow AI as the leading indicator of risk, and the weight reflects that.

### Why multipliers (not additive scoring)

Multipliers capture **compound risk.** A user with 10 medium DLP alerts is noisy but common. A user with 10 medium DLP alerts *plus* any unsanctioned AI egress *plus* a label downgrade is categorically different — and the 1.5 × 1.4 = 2.1× compound multiplier makes them rise to the top of the queue.

### Why the bands cap at 100 for "red"

Bands are calibrated against a 12-user synthetic pool generating 100 events/day per user. Under that load the top decile lands in red, the next two deciles in orange/yellow, and the long tail in green — the shape you want for a triage queue.

---

## Why SQLite (for now)

For v0.1 the priority is demo-to-disk in a single command. SQLite ships with Python, requires no external service, and is sufficient for the tens-of-thousands-of-events workload a demo or evaluation environment produces. The `storage.py` module is deliberately a thin abstraction so v0.3's Postgres + TimescaleDB migration is a drop-in swap.

---

## Extension points

**Adding a new telemetry source** — implement a `normalize_<source>(payload: dict) -> RiskEvent` function in `app/normalizer.py`, register it in the `NORMALIZERS` dispatcher dict. No other code needs to change.

**Adding a new scoring signal** — add a multiplier constant + conditional in `app/scoring.py::score_user()`. Expose it through `scoring_config()` for transparency.

**Integrating with Splunk HEC** — add a forwarder task to the `/ingest/{source}` endpoint that POSTs the normalized `RiskEvent` to HEC after persistence. Schema stays stable so Splunk-side detection content is source-agnostic.
