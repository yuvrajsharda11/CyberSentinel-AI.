"""
Shared numeric feature extraction for URL/phishing analysis.

Used by:
  - ml/train_url_model.py   (offline training)
  - services/url_detector.py (live inference, same feature order required)
"""
import math
import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rebrand.ly", "shorte.st"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk",
                    "ml", "cf", "country", "kim", "science", "gdn"}
KEYWORDS = ["login", "verify", "verification", "secure", "account", "password",
            "signin", "update", "wallet", "bank", "paypal", "confirm", "invoice",
            "suspend", "unlock", "support", "billing", "security", "reset"]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalize_url(url: str) -> str:
    original = url.strip()
    return original if re.match(r"^[a-zA-Z]+://", original) else "http://" + original


def extract_features(url: str) -> dict:
    """Returns a dict of numeric/binary features. Order-independent here;
    callers must use FEATURE_ORDER to build a fixed-order vector for the model."""
    original = url.strip()
    test_url = normalize_url(original)
    p = urlparse(test_url)
    host = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""
    full = test_url.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    digits = sum(c.isdigit() for c in host)

    return {
        "url_length": len(original),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": digits,
        "digit_ratio_host": digits / len(host) if host else 0,
        "num_subdomains": max(0, host.count(".") - 1),
        "has_at": int("@" in p.netloc),
        "has_ip": int(bool(re.search(r"^\d{1,3}(\.\d{1,3}){3}$", host))),
        "is_shortener": int(host in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "num_keywords": sum(1 for k in KEYWORDS if k in full),
        "is_https": int(p.scheme == "https"),
        "has_encoded_chars": int("%" in full),
        "has_double_slash_path": int(bool(re.search(r"//.*//", full))),
        "host_entropy": shannon_entropy(host),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9./:\-]", full)),
        "path_depth": path.count("/"),
    }


# Fixed order used for the model's input vector. Do not reorder without retraining.
FEATURE_ORDER = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots_host", "num_hyphens_host", "num_digits_host", "digit_ratio_host",
    "num_subdomains", "has_at", "has_ip", "is_shortener", "suspicious_tld",
    "num_keywords", "is_https", "has_encoded_chars", "has_double_slash_path",
    "host_entropy", "num_special_chars", "path_depth",
]
