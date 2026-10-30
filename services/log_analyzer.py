"""
Security log analyzer.

Upgrades over the original version:
  - More attack-pattern signatures (XSS, LFI/RFI, SSRF-ish, encoded/obfuscated
    PowerShell, credential stuffing hints, ransomware-note keywords).
  - Each pattern now has a severity tier, not just a numeric weight.
  - Per-source-IP aggregation: pulls IPv4 addresses out of matching lines and
    flags any single IP responsible for a burst of failed logins (brute
    force / credential stuffing), independent of overall line count.
"""
import re
from collections import Counter, defaultdict

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# (name, compiled regex, weight, severity)
PATTERNS = [
    ("Failed login", re.compile(r"failed (login|logon)|authentication failure|invalid password", re.I), 8, "medium"),
    ("Privilege event", re.compile(r"sudo|administrator|privilege|root", re.I), 4, "low"),
    ("Port scan indicator", re.compile(r"port scan|scan detected|nmap", re.I), 15, "high"),
    ("SQL injection indicator", re.compile(r"union\s+select|or\s+1=1|sql\s+injection|--\s*$|'\s*or\s*'1'='1", re.I), 25, "critical"),
    ("Path traversal indicator", re.compile(r"\.\./|\.\.\\", re.I), 20, "high"),
    ("Command injection indicator", re.compile(r";\s*(whoami|id|cat|curl|wget)|\|\s*(whoami|id)|`.*`", re.I), 25, "critical"),
    ("XSS indicator", re.compile(r"<script|onerror\s*=|javascript:", re.I), 18, "high"),
    ("Local/remote file inclusion indicator", re.compile(r"(include|require)(_once)?\s*\(.*https?://|/etc/passwd|php://filter", re.I), 22, "critical"),
    ("Encoded/obfuscated PowerShell", re.compile(r"powershell.*-enc(odedcommand)?|frombase64string", re.I), 22, "critical"),
    ("Suspicious download-and-execute", re.compile(r"(curl|wget|certutil).*(http|ftp).*(\.exe|\.sh|\.ps1)", re.I), 20, "high"),
    ("Ransomware-note keyword", re.compile(r"your files (have been|are) encrypted|pay(ment)? in bitcoin|decrypt.*instructions", re.I), 30, "critical"),
    ("Account lockout", re.compile(r"account locked|too many (failed|invalid) attempts", re.I), 6, "medium"),
    ("New admin/user created unexpectedly", re.compile(r"new (admin|administrator|user) account created|added to (admin|administrators) group", re.I), 15, "high"),
]

FAILED_LOGIN_BURST_THRESHOLD = 5


def analyze_logs(text):
    events = []
    score = 0
    severity_counts = Counter()
    lines = text.splitlines()
    failed = 0
    failed_by_ip = defaultdict(int)

    for i, line in enumerate(lines, 1):
        matched_this_line = False
        for name, pattern, weight, severity in PATTERNS:
            if pattern.search(line):
                matched_this_line = True
                ip_match = IP_RE.search(line)
                events.append({
                    "line": i,
                    "type": name,
                    "severity": severity,
                    "source_ip": ip_match.group(0) if ip_match else None,
                    "message": line[:300],
                })
                score += weight
                severity_counts[severity] += 1
                if name == "Failed login":
                    failed += 1
                    if ip_match:
                        failed_by_ip[ip_match.group(0)] += 1
        # avoid double counting a line hit by multiple patterns for the burst check below

    if failed >= FAILED_LOGIN_BURST_THRESHOLD:
        score += 15

    brute_force_ips = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in sorted(failed_by_ip.items(), key=lambda kv: -kv[1])
        if count >= FAILED_LOGIN_BURST_THRESHOLD
    ]
    if brute_force_ips:
        score += min(25, len(brute_force_ips) * 10)

    score = min(100, score)

    if score >= 70:
        verdict = "Multiple high-severity indicators — likely active attack or compromise"
    elif score >= 40:
        verdict = "Suspicious activity detected — investigate"
    else:
        verdict = "No strong attack indicators detected"

    return {
        "risk_score": score,
        "verdict": verdict,
        "line_count": len(lines),
        "event_count": len(events),
        "failed_login_count": failed,
        "severity_breakdown": dict(severity_counts),
        "brute_force_source_ips": brute_force_ips,
        "events": events[:100],
    }
