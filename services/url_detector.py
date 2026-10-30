"""
Hybrid URL / phishing detector.

Combines:
  1. A trained RandomForest classifier (ml/url_model.joblib) producing a
     phishing probability from numeric URL features.
  2. Transparent rule-based indicators (kept from the original heuristic
     engine) so the verdict stays explainable even where the model is wrong
     or unavailable.

The final risk_score blends both signals. If the model file can't be loaded
(missing dependency, not yet trained, etc.) the detector degrades gracefully
to heuristics-only and says so in the result.
"""
import re
from pathlib import Path
from urllib.parse import urlparse

from services.url_features import (
    extract_features, normalize_url, FEATURE_ORDER,
    SHORTENERS, SUSPICIOUS_TLDS, KEYWORDS,
)

MODEL_PATH = Path(__file__).resolve().parent.parent / "ml" / "url_model.joblib"

_model = None
_model_load_error = None


def _get_model():
    """Lazy-load the model once per process."""
    global _model, _model_load_error
    if _model is not None or _model_load_error is not None:
        return _model
    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
    except Exception as e:  # missing file, missing joblib/sklearn, corrupt model, etc.
        _model_load_error = str(e)
        _model = None
    return _model


def _rule_based_indicators(url: str):
    """Original transparent heuristic checks, kept for explainability."""
    original = url.strip()
    test_url = normalize_url(original)
    p = urlparse(test_url)
    host = (p.hostname or "").lower()
    full = test_url.lower()

    indicators = []
    if not host:
        indicators.append("Missing/invalid hostname")
    if len(original) > 100:
        indicators.append("Very long URL")
    if len(original) > 180:
        indicators.append("Extremely long URL")
    if "@" in p.netloc:
        indicators.append("@ symbol in network location")
    if re.search(r"https?://[^/]*https?://", full):
        indicators.append("Nested URL scheme")
    if host in SHORTENERS:
        indicators.append("URL shortener")
    if host.count(".") >= 3:
        indicators.append("Many subdomains")
    if "-" in host:
        indicators.append("Hyphenated hostname")
    if re.search(r"\d{1,3}(\.\d{1,3}){3}", host):
        indicators.append("IP address used as hostname")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        indicators.append("Higher-risk TLD indicator")
    hits = [k for k in KEYWORDS if k in full]
    if hits:
        indicators.append("Credential/urgency keyword(s): " + ", ".join(hits[:5]))
    if p.scheme != "https":
        indicators.append("Not using HTTPS")
    if "%" in full:
        indicators.append("Encoded characters present")
    if re.search(r"//.*//", full):
        indicators.append("Multiple path separators")
    return indicators, hits, p, host


def analyze_url(url: str) -> dict:
    original = url.strip()
    indicators, hits, p, host = _rule_based_indicators(original)

    rule_score = min(100, len(indicators) * 9 + (15 if len(original) > 120 else 0)
                      + (10 if hits else 0))

    model = _get_model()
    ml_probability = None
    feature_importance_hint = None
    if model is not None:
        try:
            feats = extract_features(original)
            vector = [[feats[f] for f in FEATURE_ORDER]]
            ml_probability = round(float(model.predict_proba(vector)[0][1]) * 100, 1)
            if hasattr(model, "feature_importances_"):
                top_idx = sorted(
                    range(len(FEATURE_ORDER)),
                    key=lambda i: model.feature_importances_[i],
                    reverse=True,
                )[:5]
                feature_importance_hint = [FEATURE_ORDER[i] for i in top_idx]
        except Exception:
            ml_probability = None

    if ml_probability is not None:
        # Weighted ensemble: trust the model a bit more than raw rule score,
        # but rules keep the result explainable and catch model blind spots.
        final_score = round(0.65 * ml_probability + 0.35 * rule_score)
        detection_mode = "hybrid (ML + rules)"
    else:
        final_score = rule_score
        detection_mode = "rules-only (ML model unavailable)"

    final_score = max(0, min(100, final_score))

    if final_score >= 70:
        verdict = "Likely phishing / high risk"
    elif final_score >= 40:
        verdict = "Suspicious / medium risk"
    else:
        verdict = "No strong phishing indicators detected / low risk"

    phishing_probability = ml_probability if ml_probability is not None \
        else min(99.0, max(1.0, 8 + rule_score * 0.9))

    return {
        "verdict": verdict,
        "risk_score": final_score,
        "detection_mode": detection_mode,
        "phishing_probability": phishing_probability,
        "ml_probability": ml_probability,
        "rule_score": rule_score,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "top_model_features": feature_importance_hint,
        "features": {
            "url_length": len(original),
            "hostname": host,
            "scheme": p.scheme,
            "subdomains": max(0, host.count(".")),
            "path_length": len(p.path or ""),
            "https": p.scheme == "https",
        },
    }
