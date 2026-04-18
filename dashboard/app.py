"""
ExposeBrief Streamlit Dashboard.

Four views mirroring the leadership dashboard pattern:
  1. Executive Scorecard — KPI tiles + band distribution
  2. Top Risky Users — ranked table + horizontal bar chart
  3. Shadow AI Egress — hero page: treemap + unsanctioned app inventory
  4. Event Explorer — filterable raw event table
"""
from __future__ import annotations

import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

API_BASE = os.environ.get("EXPOSEBRIEF_API", "http://localhost:8000")

BAND_COLORS = {
    "green": "#2ecc71",
    "yellow": "#f1c40f",
    "orange": "#e67e22",
    "red": "#e74c3c",
}

st.set_page_config(
    page_title="ExposeBrief",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
@st.cache_data(ttl=10)
def api_get(path: str, params: dict | None = None) -> dict | list:
    r = requests.get(f"{API_BASE}{path}", params=params or {}, timeout=10)
    r.raise_for_status()
    return r.json()


def api_post(path: str, body: dict | None = None) -> dict:
    r = requests.post(f"{API_BASE}{path}", json=body or {}, timeout=15)
    r.raise_for_status()
    return r.json()


def api_reachable() -> bool:
    try:
        requests.get(f"{API_BASE}/", timeout=3).raise_for_status()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ ExposeBrief")
    st.caption("Unified risk scoring across DLP · MIP · DSPM-for-AI")
    st.divider()

    if not api_reachable():
        st.error(f"API unreachable at {API_BASE}")
        st.stop()

    st.subheader("Demo controls")
    sim_count = st.slider("Events to generate", 50, 2000, 300, step=50)
    if st.button("▶️ Simulate telemetry", use_container_width=True, type="primary"):
        with st.spinner("Generating events..."):
            result = api_post("/simulate", {"n": sim_count})
            st.cache_data.clear()
            st.success(f"Generated {result['generated']} events")

    auto_refresh = st.toggle("Auto-refresh (10s)", value=False)
    if auto_refresh:
        st_autorefresh(interval=10_000, key="auto_refresh")

    st.divider()
    st.caption(f"API: `{API_BASE}`")
    st.caption(f"Loaded: {datetime.now().strftime('%H:%M:%S')}")


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
stats = api_get("/stats")
top_users = api_get("/risk/top", {"limit": 25})
all_events = api_get("/events", {"limit": 10000})
config = api_get("/config")

if stats["total_events"] == 0:
    st.title("ExposeBrief")
    st.info("No events yet. Click **▶️ Simulate telemetry** in the sidebar to generate demo data.")
    st.stop()

events_df = pd.DataFrame(all_events)
if not events_df.empty:
    events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])

scores_df = pd.DataFrame(top_users)


# ---------------------------------------------------------------------------
# Main tabs
# ---------------------------------------------------------------------------
tab_exec, tab_users, tab_shadow, tab_events = st.tabs(
    ["📊 Executive Scorecard", "👥 Top Risky Users", "🤖 Shadow AI Egress", "🔎 Event Explorer"]
)

# --- TAB 1: Executive Scorecard --------------------------------------------
with tab_exec:
    st.header("Executive Scorecard")
    st.caption("Aggregate risk posture across the telemetry pipeline")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Events", f"{stats['total_events']:,}")
    c2.metric("Users Observed", stats["total_users"])
    c3.metric("High-Risk Users", stats["high_risk_users"], help="Orange + Red bands")
    c4.metric("Shadow AI Events", stats["unsanctioned_ai_events"])
    c5.metric("Avg Risk Score", stats["avg_risk_score"])

    st.markdown("##### Unsanctioned AI egress volume")
    st.metric("Total MB to unsanctioned AI apps", f"{stats['unsanctioned_ai_volume_mb']:,.1f} MB")

    st.divider()

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.subheader("Risk Band Distribution")
        band_df = pd.DataFrame(
            [{"band": k, "users": v} for k, v in stats["risk_band_distribution"].items()]
        )
        fig = px.bar(
            band_df,
            x="band",
            y="users",
            color="band",
            color_discrete_map=BAND_COLORS,
            category_orders={"band": ["green", "yellow", "orange", "red"]},
        )
        fig.update_layout(showlegend=False, height=320, margin=dict(l=0, r=0, t=20, b=0))
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.subheader("Events by Source")
        if not events_df.empty:
            src_counts = events_df["source"].value_counts().reset_index()
            src_counts.columns = ["source", "count"]
            fig = px.pie(src_counts, values="count", names="source", hole=0.45)
            fig.update_layout(height=320, margin=dict(l=0, r=0, t=20, b=0))
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Event volume over time")
    if not events_df.empty:
        ts = events_df.copy()
        ts["hour"] = ts["timestamp"].dt.floor("h")
        hourly = ts.groupby(["hour", "source"]).size().reset_index(name="events")
        fig = px.area(hourly, x="hour", y="events", color="source",
                      color_discrete_sequence=px.colors.qualitative.Set2)
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=20, b=0))
        st.plotly_chart(fig, use_container_width=True)


# --- TAB 2: Top Risky Users -------------------------------------------------
with tab_users:
    st.header("Top Risky Users")
    st.caption("Ranked by composite risk score (see Scoring methodology below)")

    if not scores_df.empty:
        plot_df = scores_df.head(15).copy()
        plot_df["color"] = plot_df["risk_band"].map(BAND_COLORS)
        fig = px.bar(
            plot_df,
            x="score",
            y="user_upn",
            orientation="h",
            color="risk_band",
            color_discrete_map=BAND_COLORS,
            hover_data=["event_count", "has_unsanctioned_ai", "total_volume_mb"],
        )
        fig.update_layout(
            yaxis={"categoryorder": "total ascending"},
            height=500,
            margin=dict(l=0, r=0, t=20, b=0),
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Full ranking")
        display_df = scores_df.copy()
        display_df["top_mitre"] = display_df["top_mitre_techniques"].apply(lambda xs: ", ".join(xs[:3]))
        st.dataframe(
            display_df[["user_upn", "score", "risk_band", "event_count",
                        "has_unsanctioned_ai", "total_volume_mb", "top_mitre"]],
            use_container_width=True,
            hide_index=True,
        )

    with st.expander("ℹ️ Scoring methodology"):
        st.json(config)


# --- TAB 3: Shadow AI Egress (HERO) -----------------------------------------
with tab_shadow:
    st.header("🤖 Shadow AI Egress")
    st.caption("Unsanctioned AI application usage — the highest-weighted risk surface in ExposeBrief")

    ai_events = events_df[events_df["source"] == "dspm_ai"].copy() if not events_df.empty else pd.DataFrame()

    if ai_events.empty:
        st.info("No AI telemetry yet — simulate events to populate.")
    else:
        unsanctioned = ai_events[ai_events["is_sanctioned"] == False]  # noqa: E712

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Total AI events", len(ai_events))
        k2.metric("Unsanctioned events", len(unsanctioned))
        k3.metric("Unsanctioned apps detected", unsanctioned["destination"].nunique() if not unsanctioned.empty else 0)
        k4.metric("Unsanctioned volume (MB)", f"{unsanctioned['data_volume_mb'].sum():,.1f}" if not unsanctioned.empty else "0")

        st.subheader("Egress treemap")
        tm_df = ai_events.groupby(["is_sanctioned", "destination"]).agg(
            volume_mb=("data_volume_mb", "sum"),
            events=("event_id", "count"),
        ).reset_index()
        tm_df["category"] = tm_df["is_sanctioned"].map({True: "Sanctioned", False: "Unsanctioned"})

        fig = px.treemap(
            tm_df,
            path=["category", "destination"],
            values="volume_mb",
            color="category",
            color_discrete_map={"Sanctioned": "#27ae60", "Unsanctioned": "#e74c3c"},
            hover_data=["events"],
        )
        fig.update_layout(height=500, margin=dict(l=0, r=0, t=20, b=0))
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Top unsanctioned AI apps")
        if not unsanctioned.empty:
            app_summary = unsanctioned.groupby("destination").agg(
                events=("event_id", "count"),
                users=("user_upn", "nunique"),
                total_mb=("data_volume_mb", "sum"),
            ).reset_index().sort_values("total_mb", ascending=False)
            app_summary.columns = ["Application", "Events", "Unique Users", "Total Volume (MB)"]
            st.dataframe(app_summary, use_container_width=True, hide_index=True)


# --- TAB 4: Event Explorer --------------------------------------------------
with tab_events:
    st.header("Event Explorer")
    st.caption("Raw normalized telemetry. Filter by source, severity, or user.")

    if events_df.empty:
        st.info("No events to display.")
    else:
        f1, f2, f3 = st.columns(3)
        source_filter = f1.multiselect("Source", events_df["source"].unique(), default=list(events_df["source"].unique()))
        severity_filter = f2.multiselect("Severity", ["low", "medium", "high", "critical"],
                                         default=["low", "medium", "high", "critical"])
        user_filter = f3.selectbox("User", ["(all)"] + sorted(events_df["user_upn"].unique().tolist()))

        filtered = events_df[
            events_df["source"].isin(source_filter)
            & events_df["raw_severity"].isin(severity_filter)
        ]
        if user_filter != "(all)":
            filtered = filtered[filtered["user_upn"] == user_filter]

        st.caption(f"Showing {len(filtered):,} of {len(events_df):,} events")
        st.dataframe(
            filtered[["timestamp", "user_upn", "source", "event_type", "raw_severity",
                      "sensitivity_label", "data_volume_mb", "destination", "is_sanctioned",
                      "mitre_techniques"]].sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True,
        )
