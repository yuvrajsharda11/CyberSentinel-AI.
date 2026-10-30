"""Within-capture flow outlier detection for demonstration and triage."""
import numpy as np
from sklearn.ensemble import IsolationForest


def detect_flow_outliers(result):
    flows = result.get("top_connections_by_bytes", [])
    packets = {(x.get("source"), x.get("destination"), x.get("protocol")): x.get("packets", 0)
               for x in result.get("top_connections", [])}
    rows = []
    for flow in flows:
        key = (flow.get("source"), flow.get("destination"), flow.get("protocol"))
        size = float(flow.get("bytes", 0))
        count = float(packets.get(key, 0))
        rows.append((flow, [np.log1p(size), np.log1p(count), size / max(count, 1)]))
    if len(rows) < 4:
        return {"available": False, "reason": "At least four distinct flows are needed for a within-capture comparison.", "outliers": []}
    matrix = np.asarray([r[1] for r in rows], dtype=float)
    labels = IsolationForest(contamination="auto", random_state=17).fit_predict(matrix)
    outliers = [{**row[0], "reason": "Flow differs from other flows in this capture"}
                for row, label in zip(rows, labels) if label == -1]
    return {"available": True, "scope": "relative to this capture only", "outliers": outliers}
