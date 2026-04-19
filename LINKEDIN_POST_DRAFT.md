# ExposeBrief v0.1 — LinkedIn post draft

*Written in the established ExposeBrief voice: tension-first opening, bolded scannable layers, peer-invitation close. Edit freely — the ingredients are all here.*

---

**Most enterprises have three data-security telemetry streams. Very few have one answer to "who is risky right now?"**

That gap is what I spent this weekend shipping v0.1 of ExposeBrief to close.

ExposeBrief is a reference architecture for unifying DLP, Information Protection, and AI telemetry into a single risk surface — normalized, scored, and exposed through an API and dashboard. It treats unsanctioned AI egress as a first-class risk signal rather than an afterthought.

**What's under the hood:**

**Unified schema** — A single `RiskEvent` shape that all three sources normalize into. Every scoring, storage, and API component operates on this contract, never on raw source payloads. The normalization mapping is the hard intellectual artifact; everything else bolts onto it.

**Three pluggable ingestion paths** — Microsoft Purview DLP (Activity Explorer shape), Information Protection label events (with label-downgrade flagged as a high-signal trust-reducing action), and DSPM-for-AI / Shadow AI egress telemetry seeded with realistic unsanctioned-app inventory including foreign-AI-platform flagging.

**Transparent weighted scoring** — Composite score is base × multipliers, with every weight exposed through `GET /config`. DSPM-for-AI carries the highest source weight (0.45) because unsanctioned AI is where the modern exfiltration surface actually is. Compound multipliers capture the user who has DLP alerts *and* label downgrades *and* Shadow AI egress — the categorically different case.

**Demo-ready in one command** — `docker compose up` brings the API and Streamlit dashboard online. Click "Simulate telemetry" in the sidebar and you get 300 events across 12 synthetic users, a Shadow AI egress treemap, and a ranked top-10 risky users view in under five seconds.

**Why I built it this way:**

I'm moving toward Data Security Architect work — the role that owns the connective tissue between DLP, Information Protection, Insider Risk, and AI governance. ExposeBrief is deliberate practice in that discipline: schema design first, scoring model second, UI last. Not "a dashboard," but a demonstration that a coherent risk model is possible if you design the schema correctly.

v0.2 replaces the mock generators with real Microsoft Graph connectors and adds Splunk HEC forwarding. v0.3 brings Adaptive Protection signal fusion.

If you're designing similar pipelines — Purview → orchestration → SIEM → executive reporting — I'd genuinely love to compare notes.


`#DataSecurity #SecurityArchitecture #MicrosoftPurview #DLP #ShadowAI #AIGovernance #ZeroTrust #CloudSecurity #BuildInPublic`

---
