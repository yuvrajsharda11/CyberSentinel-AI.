"""Local cybersecurity guide and evidence-grounded assistant for saved scans."""
import ast
import json
import re
import sqlite3

from services.extended_features import map_attack


KNOWLEDGE = {
    "phishing": "Phishing is social engineering that tries to make someone disclose information, pay money, or run content. Check the sender through a separate channel, inspect the actual link host, avoid opening unexpected attachments, and report the message using your organization’s process. A scanner can identify clues but cannot prove intent.",
    "malware": "Malware is software used to disrupt systems, steal data, or gain unauthorized access. Isolate a suspected device from networks according to your incident process, preserve evidence, and contact your security team. Do not execute a suspicious file to test it; use an isolated analysis environment.",
    "sql injection": "SQL injection occurs when untrusted input changes the meaning of a database query. Use parameterized queries, avoid building SQL with string concatenation, apply least privilege to database accounts, and test inputs at trust boundaries.",
    "xss": "Cross-site scripting (XSS) occurs when untrusted content is rendered as executable browser content. Context-aware output encoding, safe templating, input handling, and a restrictive Content Security Policy reduce risk. Validate fixes with security tests.",
    "incident response": "A practical incident response sequence is: prepare; detect and analyze; contain; eradicate; recover; then document lessons. Preserve timestamps and evidence, limit access to affected systems, and follow your organization’s escalation and legal requirements.",
    "ransomware": "For suspected ransomware, isolate affected endpoints from wired and wireless networks without powering them off unless your response plan says otherwise. Preserve logs and ransom notes, protect backups from access, and coordinate containment and recovery with incident responders. Do not rely on a single indicator to confirm ransomware.",
    "firewall": "A firewall controls traffic using rules for sources, destinations, ports, protocols, and sometimes application identity. Use default-deny where practical, allow only required flows, review rules periodically, and log decisions needed for investigation.",
    "vpn": "A VPN encrypts traffic between a device and a VPN endpoint; it does not make the device or destination inherently safe. Use managed clients, strong authentication, current updates, and endpoint protection, and restrict access based on user and device posture.",
    "mfa": "Multi-factor authentication adds a second proof of identity. Prefer phishing-resistant passkeys or security keys for sensitive accounts; protect recovery methods and review unexpected authentication prompts carefully.",
    "zero trust": "Zero trust is an access approach that continuously evaluates identity, device, and request context instead of trusting network location alone. Apply least privilege, strong authentication, device health checks, and useful monitoring.",
    "password": "Use unique passwords stored in a reputable password manager, enable MFA, and change a password promptly if it may have been exposed. Avoid sharing credentials or reusing a work password on personal sites.",
    "owasp": "OWASP publishes practical application security guidance, including the OWASP Top 10 risk categories. Use it to structure threat modeling and testing, but map each recommendation to your application’s architecture and current official OWASP materials.",
    "vulnerability": "A vulnerability is a weakness that could be used to affect confidentiality, integrity, or availability. Prioritize remediation using exploitability, exposure, asset criticality, compensating controls, and current vendor guidance rather than a severity number alone.",
    "dns": "DNS translates names to records such as IP addresses. Unusual query volume or long random-looking labels can be worth investigating, but also arise from legitimate services. Correlate DNS evidence with endpoint, resolver, and network logs.",
    "pcap": "A PCAP is a packet capture. It can show observed traffic metadata and, for some unencrypted protocols, payload content. It is a time-bounded view from a particular capture point; missing traffic, NAT, encryption, and capture loss limit conclusions.",
    "log": "Security logs record events from systems and applications. Preserve original timestamps and source, normalize time zones, restrict access, and correlate events across sources. A matching text pattern is a lead for investigation, not proof of malicious activity.",
    "linux": "For Linux hardening, keep supported packages updated, remove unused services, restrict SSH, use least-privilege accounts and sudo, enforce host firewall policy, protect secrets, and forward authentication and system logs to a monitored store.",
    "windows": "For Windows hardening, keep supported systems updated, use Defender and attack-surface reduction controls, enable MFA, remove unnecessary local admin rights, use application control where practical, and centralize security event logging.",
}


def load_user_scans(db, username, limit=200):
    con = sqlite3.connect(db)
    rows = con.execute(
        """SELECT id, scan_type, target, score, result, created_at
           FROM scans WHERE username=? ORDER BY id DESC LIMIT ?""",
        (username, int(limit)),
    ).fetchall()
    con.close()
    scans = []
    for scan_id, scan_type, target, score, raw_result, created_at in rows:
        try:
            result = ast.literal_eval(raw_result)
            if not isinstance(result, dict):
                result = {}
        except (ValueError, SyntaxError, TypeError):
            result = {}
        scans.append({"id": scan_id, "type": scan_type, "target": target,
                      "score": float(score or 0), "result": result,
                      "created_at": created_at})
    return scans


def _evidence(scan):
    result = scan["result"]
    pieces = []
    for key in ("indicators", "events", "suspicious_connections", "port_scan_indicators",
                "beaconing_indicators", "dns_anomalies", "brute_force_source_ips"):
        value = result.get(key, [])
        if isinstance(value, list):
            pieces.extend(f"{key.replace('_', ' ')}: {json.dumps(item, default=str)}" for item in value[:8])
    return pieces


def _next_steps(scan):
    steps = ["Review the underlying evidence and verify it against a trusted source before taking action."]
    kind = scan["type"].upper()
    steps.extend({
        "URL": ["Open the link only in an isolated environment; verify the domain independently."],
        "PCAP": ["Check flagged hosts and time ranges against firewall, DNS, and endpoint logs."],
        "LOG": ["Correlate event timestamps and source IPs with authentication and endpoint records."],
        "FILE": ["Keep the file quarantined and compare its SHA-256 hash with a trusted source."],
        "EMAIL": ["Avoid opening links or attachments until sender identity and authentication are verified."],
    }.get(kind, []))
    return steps


def _format_scan(scan, explain=False):
    lines = [f"Scan {scan['id']} · {scan['type']} · risk {scan['score']:.0f}/100",
             f"Target: {scan['target']}", f"Time: {scan['created_at']}"]
    assessment = scan["result"].get("assessment", {})
    if assessment:
        lines.append(f"Severity: {assessment.get('severity', 'unknown')} · evidence strength: {assessment.get('confidence', 'unknown')} (heuristic label)")
        lines.append(assessment.get("confidence_basis", ""))
    evidence = _evidence(scan)
    lines.append("Evidence:" if evidence else "No structured indicators were recorded in this result.")
    lines.extend(f"  • {item}" for item in evidence[:12])
    if explain and scan["type"].upper() == "LOG":
        mappings = map_attack(scan["result"].get("events", []))
        if mappings:
            lines.append("ATT&CK references: " + "; ".join(m["technique"] for m in mappings[:6]))
    lines.append("This is a heuristic triage result, not proof of compromise or safety.")
    return "\n".join(lines)


def _general_answer(question):
    q = question.lower()
    terms = sorted(KNOWLEDGE, key=len, reverse=True)
    match = next((term for term in terms if term in q), None)
    if match:
        return KNOWLEDGE[match]
    if any(x in q for x in ("hello", "hi", "hey", "good morning", "good evening")):
        return "Hello. I can explain cybersecurity concepts or help interpret a saved URL, PCAP, log, file, or email scan. What are you investigating?"
    if any(x in q for x in ("what can you", "help", "topics", "capabilities")):
        return "I can answer common questions about phishing, malware, SQL injection, XSS, incident response, ransomware, authentication, network security, Windows/Linux hardening, OWASP, and interpreting your saved scans. My general answers use a small local reference guide; they are not live threat intelligence."
    return ("I don’t have a reliable local reference answer for that yet. Try asking about phishing, malware, SQL injection, XSS, incident response, "
            "ransomware, MFA, DNS, PCAPs, security logs, Windows/Linux hardening, or OWASP. You can also select a saved scan for evidence-based analysis.")


def answer_question(question, scans, selected_scan_id=None, mode="auto"):
    """Answer from local reference knowledge, a selected scan, or the user's scan history."""
    q = (question or "").strip().lower()
    if not q:
        return "Ask a cybersecurity question or choose a saved scan to discuss."
    chosen = next((s for s in scans if str(s["id"]) == str(selected_scan_id)), None)
    general = _general_answer(q)
    if mode == "investigation":
        if not scans:
            return "The selected investigation has no linked scans yet. Attach scans in the Investigations page or switch to a general question."
        if any(word in q for word in ("next", "recommend", "what should", "do now", "remediat")):
            guidance = []
            for scan in scans[:8]:
                guidance.extend(f"Scan {scan['id']} ({scan['type']}): {step}" for step in _next_steps(scan))
            return "Investigation triage suggestions:\n\n" + "\n".join(f"{i}. {step}" for i, step in enumerate(guidance, 1)) + "\n\nVerify each lead against independent evidence."
        return "Evidence in the selected investigation:\n\n" + "\n\n".join(_format_scan(s, explain=True) for s in scans[:8])
    asks_scan = any(word in q for word in ("scan", "finding", "result", "flagged", "my url", "this pcap", "this log", "this file", "this email", "latest", "recent", "high risk", "high-risk"))
    if mode == "general" or (mode == "auto" and not asks_scan and not chosen):
        return general
    if mode == "scan" and not chosen:
        return "Select one of your saved scans to ask about its findings. You can switch to General question at any time."
    if not scans and not chosen:
        return general
    if any(word in q for word in ("high risk", "high-risk", "critical", "highest")) and not chosen:
        selected = [scan for scan in scans if scan["score"] >= 70][:8]
        return ("Saved high-risk scans (score 70+):\n\n" + "\n\n".join(_format_scan(s) for s in selected)
                if selected else "No saved scans with risk score 70 or higher were found for your account.")
    if any(word in q for word in ("latest", "recent", "summarize", "summary")) and not chosen:
        return "Most recent saved scans:\n\n" + "\n\n".join(_format_scan(s) for s in scans[:5])
    if chosen is None:
        tokens = {t.strip(".,?!:;()[]{}\"'") for t in q.split() if len(t) > 2}
        ranked = sorted(((sum(t in (str(s["id"]) + " " + s["type"] + " " + str(s["target"]) + " " + json.dumps(s["result"], default=str)).lower() for t in tokens), s) for s in scans), key=lambda x: (x[0], x[1]["id"]), reverse=True)
        if not ranked or ranked[0][0] == 0:
            return general
        chosen = ranked[0][1]
    if any(word in q for word in ("what should", "next step", "recommend", "remediat", "do now")):
        return f"Suggested investigation steps for scan {chosen['id']}:\n\n" + "\n".join(f"{i}. {step}" for i, step in enumerate(_next_steps(chosen), 1)) + "\n\nThese are general triage suggestions, not a verdict."
    return "Evidence from your selected saved scan:\n\n" + _format_scan(chosen, explain=any(w in q for w in ("why", "explain", "evidence", "attack technique", "mitre")))
