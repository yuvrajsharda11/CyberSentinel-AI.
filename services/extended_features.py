"""Optional demonstration features that extend the core analyzers."""
import email
import ast
import hashlib
import json
import re
import sqlite3
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
ATTACK_MAP = {
    "Failed login": ("Credential Access", "T1110 — Brute Force"),
    "Privilege event": ("Privilege Escalation", "T1068 — Exploitation for Privilege Escalation"),
    "Port scan indicator": ("Discovery", "T1046 — Network Service Discovery"),
    "SQL injection indicator": ("Initial Access", "T1190 — Exploit Public-Facing Application"),
    "Path traversal indicator": ("Initial Access", "T1190 — Exploit Public-Facing Application"),
    "Command injection indicator": ("Execution", "T1059 — Command and Scripting Interpreter"),
    "XSS indicator": ("Initial Access", "T1189 — Drive-by Compromise"),
    "Encoded/obfuscated PowerShell": ("Execution", "T1059.001 — PowerShell"),
    "Suspicious download-and-execute": ("Command and Control", "T1105 — Ingress Tool Transfer"),
    "Account lockout": ("Credential Access", "T1110 — Brute Force"),
}


def init_extended_db(db):
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, username TEXT, scan_id INTEGER, label TEXT, note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    con.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, username TEXT, action TEXT, detail TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    con.execute("CREATE TABLE IF NOT EXISTS scan_workflow (scan_id INTEGER PRIMARY KEY, username TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New', owner TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    con.execute("CREATE TABLE IF NOT EXISTS investigations (id INTEGER PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New', owner TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    con.execute("CREATE TABLE IF NOT EXISTS investigation_scans (investigation_id INTEGER NOT NULL, scan_id INTEGER NOT NULL, username TEXT NOT NULL, PRIMARY KEY(investigation_id,scan_id))")
    try:
        con.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
    except sqlite3.OperationalError:
        pass
    con.execute("UPDATE users SET role='admin' WHERE username='admin'")
    bootstrap = __import__("os").getenv("CYBERSENTINEL_ADMIN_USERNAME", "").strip()
    if bootstrap:
        con.execute("UPDATE users SET role='admin' WHERE username=?", (bootstrap,))
    con.commit(); con.close()


def set_scan_workflow(db, username, scan_id, status, owner="", note=""):
    if status not in {"New", "Reviewing", "Confirmed", "Benign", "Resolved"}:
        return False
    con = sqlite3.connect(db)
    exists = con.execute("SELECT 1 FROM scans WHERE id=? AND username=?", (int(scan_id), username)).fetchone()
    if not exists:
        con.close()
        return False
    con.execute("INSERT INTO scan_workflow(scan_id,username,status,owner,note,updated_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(scan_id) DO UPDATE SET status=excluded.status,owner=excluded.owner,note=excluded.note,updated_at=CURRENT_TIMESTAMP",
                (int(scan_id), username, status, owner[:100], note[:1000]))
    con.commit(); con.close()
    record_audit(db, username, "workflow_update", f"scan={scan_id}; status={status}")
    return True


def workflow_for(db, username, scan_id):
    con = sqlite3.connect(db)
    row = con.execute("SELECT status,owner,note,updated_at FROM scan_workflow WHERE scan_id=? AND username=?", (int(scan_id), username)).fetchone()
    con.close()
    return row or ("New", "", "", "")


def delete_old_scans(db, username, days):
    days = max(30, min(int(days), 3650))
    con = sqlite3.connect(db)
    ids = [r[0] for r in con.execute("SELECT id FROM scans WHERE username=? AND julianday(created_at) < julianday('now', ?)", (username, f"-{days} days")).fetchall()]
    if ids:
        con.executemany("DELETE FROM scan_workflow WHERE scan_id=?", [(i,) for i in ids])
        con.executemany("DELETE FROM investigation_scans WHERE scan_id=? AND username=?", [(i, username) for i in ids])
        con.executemany("DELETE FROM feedback WHERE username=? AND scan_id=?", [(username, i) for i in ids])
        con.executemany("DELETE FROM scans WHERE username=? AND id=?", [(username, i) for i in ids])
    con.commit(); con.close()
    record_audit(db, username, "retention_delete", f"deleted={len(ids)}; older_than_days={days}")
    return len(ids)


def list_investigations(db, username):
    con = sqlite3.connect(db)
    rows = con.execute("SELECT id,name,status,owner,notes,created_at,updated_at FROM investigations WHERE username=? ORDER BY updated_at DESC", (username,)).fetchall()
    con.close()
    return rows


def create_investigation(db, username, name):
    name = (name or "").strip()[:160]
    if not name:
        return None
    con = sqlite3.connect(db)
    cur = con.execute("INSERT INTO investigations(username,name) VALUES(?,?)", (username, name))
    investigation_id = cur.lastrowid
    con.commit(); con.close()
    record_audit(db, username, "investigation_create", f"investigation={investigation_id}")
    return investigation_id


def update_investigation(db, username, investigation_id, status, owner, notes):
    if status not in {"New", "Reviewing", "Confirmed", "Benign", "Resolved"}:
        return False
    con = sqlite3.connect(db)
    cur = con.execute("UPDATE investigations SET status=?,owner=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND username=?",
                      (status, owner[:100], notes[:2000], int(investigation_id), username))
    ok = cur.rowcount > 0
    con.commit(); con.close()
    if ok: record_audit(db, username, "investigation_update", f"investigation={investigation_id}; status={status}")
    return ok


def attach_investigation_scans(db, username, investigation_id, scan_ids):
    con = sqlite3.connect(db)
    owned = con.execute("SELECT 1 FROM investigations WHERE id=? AND username=?", (int(investigation_id), username)).fetchone()
    if not owned:
        con.close(); return False
    valid = {r[0] for r in con.execute("SELECT id FROM scans WHERE username=?", (username,)).fetchall()}
    chosen = sorted({int(s) for s in scan_ids if int(s) in valid})
    con.execute("DELETE FROM investigation_scans WHERE investigation_id=? AND username=?", (int(investigation_id), username))
    con.executemany("INSERT INTO investigation_scans(investigation_id,scan_id,username) VALUES(?,?,?)", [(int(investigation_id), s, username) for s in chosen])
    con.commit(); con.close()
    record_audit(db, username, "investigation_scans", f"investigation={investigation_id}; scan_count={len(chosen)}")
    return True


def investigation_detail(db, username, investigation_id):
    con = sqlite3.connect(db)
    row = con.execute("SELECT id,name,status,owner,notes,created_at,updated_at FROM investigations WHERE id=? AND username=?", (int(investigation_id), username)).fetchone()
    if not row:
        con.close(); return None, []
    scans = con.execute("SELECT s.id,s.scan_type,s.target,s.score,s.created_at FROM scans s JOIN investigation_scans x ON x.scan_id=s.id WHERE x.investigation_id=? AND x.username=? AND s.username=? ORDER BY s.id DESC", (int(investigation_id), username, username)).fetchall()
    con.close()
    return row, scans


def record_audit(db, username, action, detail=""):
    con = sqlite3.connect(db)
    con.execute("INSERT INTO audit_events(username,action,detail) VALUES(?,?,?)", (username, action, str(detail)[:500]))
    con.commit(); con.close()


def add_feedback(db, username, scan_id, label, note):
    con = sqlite3.connect(db)
    con.execute("INSERT INTO feedback(username,scan_id,label,note) VALUES(?,?,?,?)", (username, int(scan_id), label, note[:500]))
    con.commit(); con.close()
    record_audit(db, username, "feedback", f"scan={scan_id}; label={label}")


def role_for(db, username):
    con = sqlite3.connect(db)
    row = con.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    return row[0] if row else "analyst"


def set_role(db, actor, username, role):
    if role not in {"admin", "analyst"} or username == actor:
        return False
    con = sqlite3.connect(db)
    con.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    changed = con.total_changes > 0
    con.commit(); con.close()
    if changed: record_audit(db, actor, "role_change", f"user={username}; role={role}")
    return changed


def feedback_frame(db, username, admin=False):
    con = sqlite3.connect(db)
    if admin:
        rows = con.execute("SELECT username,scan_id,label,note,created_at FROM feedback ORDER BY id DESC LIMIT 500").fetchall()
    else:
        rows = con.execute("SELECT username,scan_id,label,note,created_at FROM feedback WHERE username=? ORDER BY id DESC LIMIT 200", (username,)).fetchall()
    con.close()
    return rows


def audit_frame(db, username, admin=False):
    con = sqlite3.connect(db)
    if admin:
        rows = con.execute("SELECT username,action,detail,created_at FROM audit_events ORDER BY id DESC LIMIT 500").fetchall()
    else:
        rows = con.execute("SELECT username,action,detail,created_at FROM audit_events WHERE username=? ORDER BY id DESC LIMIT 200", (username,)).fetchall()
    con.close()
    return rows


def compare_scans(db, username, first_id, second_id):
    con = sqlite3.connect(db)
    rows = con.execute("SELECT id,scan_type,target,score,result FROM scans WHERE username=? AND id IN (?,?)", (username, int(first_id), int(second_id))).fetchall()
    con.close()
    return rows


def incident_timeline(db, username):
    con = sqlite3.connect(db)
    rows = con.execute("SELECT id,scan_type,target,score,result,created_at FROM scans WHERE username=? ORDER BY created_at DESC LIMIT 500", (username,)).fetchall()
    con.close()
    timeline, occurrences = [], {}
    for scan_id, scan_type, target, score, raw, created_at in rows:
        timeline.append({"time": created_at, "scan_id": scan_id, "type": scan_type, "target": target, "risk": score})
        try:
            parsed = ast.literal_eval(raw)
            iocs = extract_iocs(json.dumps(parsed, default=str))
            for kind, values in iocs.items():
                for value in values:
                    occurrences.setdefault((kind, value), []).append(scan_id)
        except Exception:
            continue
    related = [{"type": kind, "indicator": value, "scan_ids": sorted(set(ids))}
               for (kind, value), ids in occurrences.items() if len(set(ids)) > 1]
    return timeline, related


def extract_iocs(text):
    urls = sorted(set(URL_RE.findall(text)))
    ips = sorted(set(IP_RE.findall(text)))
    hashes = sorted(set(HASH_RE.findall(text)))
    domains = sorted({urlparse(u).hostname for u in urls if urlparse(u).hostname})
    return {"URLs": urls, "Domains": domains, "IP addresses": ips, "File hashes": hashes}


def analyze_email(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body_parts = []
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_filename():
                payload = part.get_payload(decode=True) or b""
                attachments.append({"filename": part.get_filename()[:200],
                                    "content_type": part.get_content_type(),
                                    "size_bytes": len(payload),
                                    "sha256": hashlib.sha256(payload).hexdigest()})
            if part.get_content_type() == "text/plain":
                try: body_parts.append(part.get_content())
                except Exception: pass
    else:
        try: body_parts.append(msg.get_content())
        except Exception: body_parts.append(raw.decode("utf-8", "replace"))
    body = "\n".join(str(x) for x in body_parts)
    sender = email.utils.parseaddr(msg.get("From", ""))[1].lower()
    reply = email.utils.parseaddr(msg.get("Reply-To", ""))[1].lower()
    indicators = []
    if reply and sender and reply.split("@")[-1] != sender.split("@")[-1]: indicators.append("Reply-To domain differs from sender domain")
    auth = (msg.get("Authentication-Results", "") + " " + msg.get("Received-SPF", "")).lower()
    if auth and ("spf=fail" in auth or "dkim=fail" in auth or "dmarc=fail" in auth): indicators.append("An email authentication check failed")
    if not auth: indicators.append("No SPF/DKIM/DMARC result found in supplied headers")
    if re.search(r"urgent|immediately|suspended|verify your|password expires|payment required", body, re.I): indicators.append("Urgent or credential/payment pressure language")
    urls = URL_RE.findall(body)
    if len(urls) > 3: indicators.append("Message contains multiple links")
    score = min(100, len(indicators) * 20 + (15 if urls else 0))
    return {"risk_score": score, "sender": sender, "reply_to": reply, "subject": str(msg.get("Subject", "")), "urls": urls, "attachments": attachments, "indicators": indicators, "summary": "Review sender identity, authentication results, links, and attachment hashes before interacting. Hashes are calculated locally."}


def answer_log_query(question, events):
    q = question.lower()
    selected = events
    if "failed login" in q or "failed login" in q or "brute" in q:
        selected = [e for e in events if "login" in str(e.get("type", "")).lower()]
    elif "critical" in q or "high severity" in q:
        selected = [e for e in events if e.get("severity") in {"critical", "high"}]
    elif "ip" in q:
        selected = [e for e in events if e.get("source_ip")]
    return {"matched_count": len(selected), "events": selected[:100], "explanation": "This assistant uses transparent filters over extracted log events; it does not send log data to an external language model."}


def map_attack(events):
    output = []
    seen = set()
    for event in events:
        mapping = ATTACK_MAP.get(event.get("type"))
        if mapping and mapping not in seen:
            seen.add(mapping)
            output.append({"tactic": mapping[0], "technique": mapping[1], "evidence": event.get("type")})
    return output
