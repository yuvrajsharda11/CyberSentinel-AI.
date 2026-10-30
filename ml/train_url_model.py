"""Train the URL model on the UCI PhiUSIIL corpus or the synthetic demo set.

Default: use ml/data/phiusiil-dataset.zip when present. Use --synthetic to
reproduce the old teaching baseline. Evaluation is grouped by registrable
domain to keep a domain out of both train and test partitions.
"""
import argparse
import csv
import json
import random
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, precision_score,
                             recall_score, f1_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

sys.path.append(str(Path(__file__).resolve().parent.parent))
from services.url_features import extract_features, FEATURE_ORDER  # noqa: E402

HERE = Path(__file__).resolve().parent
DATASET = HERE / "data" / "phiusiil-dataset.zip"
RANDOM_SEED = 42


def _rand_str(n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(random.choice(alphabet) for _ in range(n))


LEGIT_BRANDS = ["google", "microsoft", "apple", "amazon", "wikipedia", "github",
                "netflix", "spotify", "linkedin", "reddit", "nytimes", "bbc"]
LEGIT_TLDS = ["com", "org", "net", "io", "edu", "gov", "co.uk"]
PHISH_TLDS = ["zip", "top", "xyz", "click", "work", "gq", "tk", "ml", "cf", "country", "kim"]
BRAND_KEYWORDS = ["login", "verify", "secure", "account", "signin", "update",
                  "wallet", "confirm", "billing", "support", "reset", "unlock"]
WORDS = ["docs", "help", "shop", "news", "media", "cloud", "app", "portal", "team", "blog", "store", "mail"]


def _synthetic_dataset(n_per_class=4000):
    urls, labels = [], []
    for _ in range(n_per_class):
        brand, tld = random.choice(LEGIT_BRANDS), random.choice(LEGIT_TLDS)
        style = random.random()
        host = f"{brand}.{tld}" if style < .5 else (f"{random.choice(WORDS)}.{brand}.{tld}" if style < .8 else f"www.{brand}.{tld}")
        path = "/" + "/".join(random.choice(WORDS) for _ in range(random.randint(0, 2)))
        urls.append(f"https://{host}{path}"); labels.append(0)

        brand, kw = random.choice(LEGIT_BRANDS), random.choice(BRAND_KEYWORDS)
        pattern = random.choice(["ip", "lookalike", "tld", "subdomains", "shortener", "keyword"])
        if pattern == "ip":
            host = ".".join(str(random.randint(1, 254)) for _ in range(4)); u = f"http://{host}/{kw}/{brand}-{_rand_str(6)}"
        elif pattern == "lookalike": u = f"http://{brand}-{kw}.{random.choice(PHISH_TLDS)}/{_rand_str(8)}"
        elif pattern == "tld": u = f"https://{brand}{_rand_str(3)}.{random.choice(PHISH_TLDS)}/{kw}"
        elif pattern == "subdomains":
            subs = ".".join(_rand_str(random.randint(4, 8)) for _ in range(random.randint(3, 5)))
            u = f"http://{subs}.{brand}.{random.choice(PHISH_TLDS)}/{kw}.php"
        elif pattern == "shortener": u = f"http://{random.choice(['bit.ly','tinyurl.com','t.co','cutt.ly','rebrand.ly'])}/{_rand_str(7)}"
        else: u = f"http://{kw}-{brand}-{_rand_str(5)}.{random.choice(PHISH_TLDS + ['com'])}/{kw}/{kw}/{_rand_str(10)}.html?{kw}={_rand_str(6)}"
        urls.append(u); labels.append(1)
    return urls, np.asarray(labels, dtype=np.int8)


def _registrable_domain(url):
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level_suffixes = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au",
                          "co.nz", "com.br", "com.cn", "com.sg", "co.jp", "co.in"}
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in two_level_suffixes else ".".join(labels[-2:])


def _load_phiusiil(path):
    """Return raw URLs and phishing labels. UCI: label 0 phishing, label 1 legit."""
    rows = []
    with zipfile.ZipFile(path) as archive:
        csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
        if len(csv_names) != 1:
            raise ValueError("Expected exactly one CSV file in the PhiUSIIL archive.")
        with archive.open(csv_names[0]) as raw:
            reader = csv.DictReader((line.decode("utf-8-sig", errors="replace") for line in raw))
            if not {"URL", "label"}.issubset(reader.fieldnames or []):
                raise ValueError("Dataset must contain URL and label columns.")
            for row in reader:
                url = (row.get("URL") or "").strip()
                try:
                    label = int(row.get("label", ""))
                except ValueError:
                    continue
                if url and label in (0, 1):
                    rows.append((url, 1 if label == 0 else 0))
    if not rows:
        raise ValueError("No labeled URLs were found in the dataset.")
    urls, labels = zip(*rows)
    return list(urls), np.asarray(labels, dtype=np.int8)


def _metrics(y_true, y_pred, probabilities):
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(x) for x in matrix.ravel()]
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_phishing": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall_phishing": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_phishing": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "false_negative_rate": round(fn / max(1, fn + tp), 4),
        "specificity": round(tn / max(1, tn + fp), 4),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 4),
        "confusion_matrix": {"labels": ["legitimate", "phishing"],
                             "true_negative": tn, "false_positive": fp,
                             "false_negative": fn, "true_positive": tp},
        "test_samples": int(len(y_true)),
    }


def train(use_synthetic=False, dataset_path=DATASET):
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)
    old_metadata = {}
    metadata_path = HERE / "model_metadata.json"
    if metadata_path.exists():
        try:
            old_metadata = json.loads(metadata_path.read_text())
        except Exception:
            pass

    if use_synthetic or not Path(dataset_path).exists():
        urls, y = _synthetic_dataset()
        groups = None
        dataset_name = "Programmatically generated synthetic URL patterns"
        dataset_url = None
        license_name = "Synthetic examples generated by this project"
        split_name = "stratified random 80/20 split; synthetic rows"
    else:
        urls, y = _load_phiusiil(dataset_path)
        groups = np.asarray([_registrable_domain(url) for url in urls])
        dataset_name = "PhiUSIIL Phishing URL (Website) Dataset"
        dataset_url = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
        license_name = "CC BY 4.0; attribution required"
        split_name = "80/20 GroupShuffleSplit by registrable domain; seed 42"

    X = np.asarray([[extract_features(url).get(feature, 0) for feature in FEATURE_ORDER]
                    for url in urls], dtype=float)
    indices = np.arange(len(y))
    if groups is None:
        train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=RANDOM_SEED, stratify=y)
        train_domain_count = test_domain_count = None
    else:
        split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_SEED)
        train_idx, test_idx = next(split.split(X, y, groups))
        train_domain_count = int(len(set(groups[train_idx])))
        test_domain_count = int(len(set(groups[test_idx])))
        assert not (set(groups[train_idx]) & set(groups[test_idx]))

    model = RandomForestClassifier(n_estimators=160, max_depth=12, min_samples_leaf=3,
                                   random_state=RANDOM_SEED, class_weight="balanced",
                                   n_jobs=-1)
    model.fit(X[train_idx], y[train_idx])
    pred = model.predict(X[test_idx])
    proba = model.predict_proba(X[test_idx])[:, 1]
    metrics = _metrics(y[test_idx], pred, proba)
    metadata = {
        "dataset": dataset_name, "dataset_url": dataset_url,
        "license": license_name, "dataset_samples": int(len(y)),
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "split": split_name, "seed": RANDOM_SEED,
        "group_counts": {"train_domains": train_domain_count, "test_domains": test_domain_count},
        "metrics": metrics, "feature_order": FEATURE_ORDER,
        "feature_importances": dict(zip(FEATURE_ORDER, [round(float(v), 5) for v in model.feature_importances_])),
        "synthetic_demo_metrics": old_metadata.get("synthetic_demo_metrics") or {
            "accuracy": old_metadata.get("held_out_accuracy"),
            "roc_auc": old_metadata.get("held_out_auc"),
            "dataset": old_metadata.get("trained_on", "synthetic dataset"),
        },
        "limitations": ["Domain-grouped evaluation reduces same-domain leakage but does not replace a time-based external validation set.",
                        "PhiUSIIL labels and collection process have the limitations documented by UCI.",
                        "This model uses URL-string features only; dataset webpage features are not used."],
    }
    joblib.dump(model, HERE / "url_model.joblib")
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(json.dumps({"dataset": dataset_name, "metrics": metrics, "groups": metadata["group_counts"]}, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(DATASET), help="PhiUSIIL CSV or single-CSV ZIP archive")
    parser.add_argument("--synthetic", action="store_true", help="Train the synthetic teaching baseline")
    args = parser.parse_args()
    train(use_synthetic=args.synthetic, dataset_path=args.dataset)


if __name__ == "__main__":
    main()
