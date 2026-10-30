"""Re-evaluate the saved URL model on the domain-held-out PhiUSIIL split."""
import argparse
import json
from pathlib import Path
import sys

import joblib
import numpy as np
from sklearn.model_selection import GroupShuffleSplit

sys.path.append(str(Path(__file__).resolve().parent.parent))
from train_url_model import DATASET, RANDOM_SEED, _load_phiusiil, _metrics, _registrable_domain
from services.url_features import extract_features, FEATURE_ORDER

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(DATASET))
    args = parser.parse_args()
    urls, y = _load_phiusiil(args.dataset)
    groups = np.asarray([_registrable_domain(url) for url in urls])
    split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_SEED)
    train_idx, test_idx = next(split.split(np.zeros(len(y)), y, groups))
    model = joblib.load(HERE / "url_model.joblib")
    metadata = json.loads((HERE / "model_metadata.json").read_text())
    if metadata.get("dataset") != "PhiUSIIL Phishing URL (Website) Dataset":
        raise SystemExit("The saved model was not trained on the PhiUSIIL training partition; retrain with python ml/train_url_model.py first.")
    if not set(groups[train_idx]).isdisjoint(set(groups[test_idx])):
        raise SystemExit("Domain grouping failed; refusing to report contaminated metrics.")
    X = np.asarray([[extract_features(url).get(feature, 0) for feature in FEATURE_ORDER]
                    for url in (urls[i] for i in test_idx)], dtype=float)
    y_test = y[test_idx]
    result = _metrics(y_test, model.predict(X), model.predict_proba(X)[:, 1])
    print(json.dumps({"dataset": metadata["dataset"], "split": metadata["split"], "metrics": result}, indent=2))


if __name__ == "__main__":
    main()
