"""Risk tier and uncalibrated evidence-strength summaries for scan results."""


def assess(scan_type, result, risk_score):
    score = float(risk_score or 0)
    severity = "high" if score >= 70 else "medium" if score >= 40 else "low"
    if result.get("error"):
        return {"severity": severity, "confidence": "unavailable",
                "confidence_basis": "The analyzer could not complete this input."}

    if scan_type == "URL":
        ml = result.get("ml_probability")
        rule = result.get("rule_score")
        if ml is None:
            confidence, basis = "low", "Rules only; no calibrated confidence is available."
        elif rule is not None and abs(float(ml) - float(rule)) <= 20:
            confidence, basis = "moderate", "The model score and rule score broadly agree; this is not a calibrated probability."
        else:
            confidence, basis = "low", "Model and rule signals are unavailable or disagree; this is not a calibrated probability."
        return {"severity": severity, "confidence": confidence, "confidence_basis": basis}

    evidence_keys = {
        "PCAP": ("suspicious_connections", "port_scan_indicators", "beaconing_indicators", "dns_anomalies"),
        "LOG": ("events", "brute_force_source_ips"),
        "FILE": ("indicators",),
        "EMAIL": ("indicators", "urls", "attachments"),
        "IMAGE": ("indicators", "qr_payloads", "url_results"),
    }.get(scan_type, ("indicators",))
    present = [key for key in evidence_keys if result.get(key)]
    total = sum(len(result.get(key, [])) for key in present if isinstance(result.get(key), list))
    if len(present) >= 2 and total >= 3:
        confidence, basis = "moderate", f"Evidence appears in {len(present)} signal groups; this is a heuristic strength label, not a probability."
    elif total:
        confidence, basis = "low", "One or a few heuristic signal groups were found; verify independently."
    else:
        confidence, basis = "low", "No structured indicators were recorded; absence of findings does not establish safety."
    return {"severity": severity, "confidence": confidence, "confidence_basis": basis}
