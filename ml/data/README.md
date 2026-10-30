# URL evaluation dataset

`phiusiil-dataset.zip` contains the PhiUSIIL Phishing URL (Website) Dataset from the UCI Machine Learning Repository, dataset 967: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

- 235,795 labeled URL rows: 134,850 legitimate and 100,945 phishing.
- UCI label mapping: `1` is legitimate; `0` is phishing. The project maps these to `0` and `1` respectively for model training.
- License: Creative Commons Attribution 4.0 International (CC BY 4.0).
- Citation: Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) [Dataset].* UCI Machine Learning Repository. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset. The UCI record cites the related paper in *Computers & Security* (2024): https://doi.org/10.1016/j.cose.2023.103545.
- The project uses only the raw `URL` and `label` columns. Other webpage-derived dataset features are excluded.
- The project splits by normalized registrable domain (80/20, fixed seed) so domains do not appear on both sides. The source does not provide a suitable temporal holdout, so this is not a time-based external evaluation.

Run `python ml/train_url_model.py` to train and produce metrics from this dataset. Use `python ml/train_url_model.py --synthetic` only to reproduce the clearly marked synthetic teaching baseline.
