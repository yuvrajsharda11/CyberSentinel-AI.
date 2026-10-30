"""
Cross-scan risk aggregation.

The original version just averaged raw scores. This adds:
  - Recency weighting: recent scans matter more than old ones for an
    "overall current risk" figure (exponential decay).
  - A severity-tier breakdown so the dashboard can show counts, not just
    one number.
  - A simple trend indicator (rising / falling / stable) comparing the
    weighted-recent average to the older average.
"""
import math
from datetime import datetime


def calculate_risk(*scores):
    """Backwards-compatible simple average, kept for any direct callers."""
    vals = [float(x) for x in scores if x is not None]
    return round(sum(vals) / len(vals), 2) if vals else 0


def severity_tier(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def summarize_history(history_df):
    """history_df: a pandas DataFrame with at least 'score' and 'created_at'
    columns (created_at as ISO strings, most-recent-first is fine either way).
    Returns a dict of summary stats for the dashboard."""
    if history_df is None or len(history_df) == 0:
        return {
            "overall_score": 0, "tier": "low", "trend": "no data",
            "counts": {"high": 0, "medium": 0, "low": 0},
        }

    df = history_df.copy()
    counts = {
        "high": int((df["score"] >= 70).sum()),
        "medium": int(((df["score"] >= 40) & (df["score"] < 70)).sum()),
        "low": int((df["score"] < 40).sum()),
    }

    try:
        df["_ts"] = df["created_at"].apply(lambda s: datetime.fromisoformat(s))
        now = df["_ts"].max()
        # half-life of ~7 days for weighting
        df["_age_days"] = (now - df["_ts"]).dt.total_seconds() / 86400.0
        df["_weight"] = df["_age_days"].apply(lambda d: math.exp(-d / 7.0))
        weighted_overall = round((df["score"] * df["_weight"]).sum() / df["_weight"].sum(), 1)

        midpoint = df["_ts"].min() + (now - df["_ts"].min()) / 2
        recent = df[df["_ts"] >= midpoint]
        older = df[df["_ts"] < midpoint]
        recent_avg = recent["score"].mean() if len(recent) else weighted_overall
        older_avg = older["score"].mean() if len(older) else recent_avg
        if recent_avg - older_avg > 5:
            trend = "rising"
        elif older_avg - recent_avg > 5:
            trend = "falling"
        else:
            trend = "stable"
    except Exception:
        weighted_overall = round(df["score"].mean(), 1)
        trend = "unknown"

    return {
        "overall_score": weighted_overall,
        "tier": severity_tier(weighted_overall),
        "trend": trend,
        "counts": counts,
    }
