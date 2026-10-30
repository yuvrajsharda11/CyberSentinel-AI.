"""Cybercrime case records, private evidence storage, and case exports."""
from __future__ import annotations

import csv
import ast
import hashlib
import io
import json
import os
import re
import sqlite3
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

CASE_TYPES = (
    "Phishing / impersonation", "Online payment fraud", "Account takeover",
    "Identity theft", "Extortion / ransomware", "Other",
)
CASE_STATUSES = ("New", "In Review", "Reported", "Resolved", "Closed")
INDICATOR_TYPES = (
    "URL", "Domain", "IP address", "Email", "Phone", "File hash",
    "Payment reference", "Crypto wallet", "Account identifier",
)
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
MAX_EVIDENCE_PER_CASE = 20
MAX_CASE_EVIDENCE_BYTES = 100 * 1024 * 1024


@contextmanager
def _connect(db):
    con = sqlite3.connect(db, timeout=20)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _evidence_path(username, case_id, evidence_id):
    owner_folder = hashlib.sha256(username.encode("utf-8")).hexdigest()[:24]
    return (Path(os.getenv("CYBERSENTINEL_EVIDENCE_DIR", "data/evidence")).resolve()
            / owner_folder / str(int(case_id)) / f"{evidence_id}.blob")


def init_cybercrime_db(db):
    with _connect(db) as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS cybercrime_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            description TEXT NOT NULL DEFAULT '',
            incident_at TEXT NOT NULL DEFAULT '',
            victim_contact TEXT NOT NULL DEFAULT '',
            payment_details TEXT NOT NULL DEFAULT '',
            extortion_details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_cybercrime_cases_owner ON cybercrime_cases(username,updated_at);
        CREATE TABLE IF NOT EXISTS cybercrime_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            event_at TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_cybercrime_events_case ON cybercrime_events(username,case_id,event_at);
        CREATE TABLE IF NOT EXISTS cybercrime_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL UNIQUE,
            case_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            content_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_cybercrime_evidence_case ON cybercrime_evidence(username,case_id);
        CREATE TABLE IF NOT EXISTS cybercrime_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id,indicator_type,normalized_value)
        );
        CREATE INDEX IF NOT EXISTS idx_cybercrime_ioc_match ON cybercrime_indicators(username,indicator_type,normalized_value);
        CREATE TABLE IF NOT EXISTS cybercrime_case_scans (
            case_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            PRIMARY KEY(case_id,scan_id)
        );
        """)


def list_cases(db, username):
    with _connect(db) as con:
        return [dict(row) for row in con.execute(
            "SELECT id,category,title,status,incident_at,created_at,updated_at FROM cybercrime_cases "
            "WHERE username=? ORDER BY updated_at DESC,id DESC", (username,))]


def create_case(db, username, category, title, description="", incident_at="",
                victim_contact="", payment_details="", extortion_details=""):
    title = (title or "").strip()[:180]
    if category not in CASE_TYPES or not title:
        return None
    with _connect(db) as con:
        cur = con.execute(
            "INSERT INTO cybercrime_cases(username,category,title,description,incident_at,victim_contact,payment_details,extortion_details) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (username, category, title, (description or "")[:5000], (incident_at or "")[:80],
             (victim_contact or "")[:500], (payment_details or "")[:3000], (extortion_details or "")[:3000]))
        case_id = cur.lastrowid
        con.execute("INSERT INTO cybercrime_events(case_id,username,event_at,summary) VALUES(?,?,?,?)",
                    (case_id, username, (incident_at or datetime.now().astimezone().isoformat())[:80],
                     "Case intake recorded; incident details are user-reported."))
        return case_id


def get_case(db, username, case_id):
    with _connect(db) as con:
        row = con.execute("SELECT * FROM cybercrime_cases WHERE id=? AND username=?",
                          (int(case_id), username)).fetchone()
        return dict(row) if row else None


def update_case(db, username, case_id, category, title, status, description,
                incident_at, victim_contact, payment_details, extortion_details):
    if category not in CASE_TYPES or status not in CASE_STATUSES or not (title or "").strip():
        return False
    with _connect(db) as con:
        cur = con.execute(
            "UPDATE cybercrime_cases SET category=?,title=?,status=?,description=?,incident_at=?,victim_contact=?,"
            "payment_details=?,extortion_details=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND username=?",
            (category, title.strip()[:180], status, (description or "")[:5000], (incident_at or "")[:80],
             (victim_contact or "")[:500], (payment_details or "")[:3000], (extortion_details or "")[:3000],
             int(case_id), username))
        return cur.rowcount > 0


def add_case_event(db, username, case_id, event_at, summary):
    summary = (summary or "").strip()[:2000]
    if not summary or not get_case(db, username, case_id):
        return False
    with _connect(db) as con:
        con.execute("INSERT INTO cybercrime_events(case_id,username,event_at,summary) VALUES(?,?,?,?)",
                     (int(case_id), username, (event_at or "")[:80], summary))
        con.execute("UPDATE cybercrime_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=? AND username=?",
                    (int(case_id), username))
    return True


def list_case_events(db, username, case_id):
    with _connect(db) as con:
        return [dict(row) for row in con.execute(
            "SELECT id,event_at,summary,created_at FROM cybercrime_events WHERE case_id=? AND username=? "
            "ORDER BY event_at,id", (int(case_id), username))]


def add_evidence(db, username, case_id, filename, content_type, evidence_type, data):
    """Write evidence under a random private path and record its SHA-256."""
    if not data or len(data) > MAX_EVIDENCE_BYTES or not get_case(db, username, case_id):
        return None, "Evidence must be non-empty, at most 25 MB, and attached to your case."
    with _connect(db) as con:
        count, total_bytes = con.execute(
            "SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM cybercrime_evidence WHERE case_id=? AND username=?",
            (int(case_id), username)).fetchone()
    if count >= MAX_EVIDENCE_PER_CASE:
        return None, f"A case can contain at most {MAX_EVIDENCE_PER_CASE} evidence files."
    if total_bytes + len(data) > MAX_CASE_EVIDENCE_BYTES:
        return None, "A case can store at most 100 MB of evidence."

    evidence_id = uuid.uuid4().hex
    root = Path(os.getenv("CYBERSENTINEL_EVIDENCE_DIR", "data/evidence")).resolve()
    owner_folder = hashlib.sha256(username.encode("utf-8")).hexdigest()[:24]
    case_folder = root / owner_folder / str(int(case_id))
    case_folder.mkdir(parents=True, exist_ok=True)
    stored = case_folder / f"{evidence_id}.blob"
    temp = case_folder / f".{evidence_id}.tmp"
    digest = hashlib.sha256(data).hexdigest()
    safe_filename = Path((filename or "evidence").replace("\\", "/")).name[:200] or "evidence"
    safe_filename = re.sub(r"[^A-Za-z0-9._ -]", "_", safe_filename).strip(" .") or "evidence"
    try:
        with temp.open("xb") as stream:
            stream.write(data)
        temp.replace(stored)
        with _connect(db) as con:
            con.execute(
                "INSERT INTO cybercrime_evidence(evidence_id,case_id,username,filename,evidence_type,content_type,size_bytes,sha256,stored_path) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (evidence_id, int(case_id), username, safe_filename, (evidence_type or "Other")[:80],
                 (content_type or "application/octet-stream")[:120], len(data), digest, str(stored)))
            con.execute("UPDATE cybercrime_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=? AND username=?",
                        (int(case_id), username))
    except Exception:
        temp.unlink(missing_ok=True)
        stored.unlink(missing_ok=True)
        raise
    return {"evidence_id": evidence_id, "filename": safe_filename, "sha256": digest}, None


def list_case_evidence(db, username, case_id):
    with _connect(db) as con:
        return [dict(row) for row in con.execute(
            "SELECT id,evidence_id,filename,evidence_type,content_type,size_bytes,sha256,created_at,stored_path "
            "FROM cybercrime_evidence WHERE case_id=? AND username=? ORDER BY id",
            (int(case_id), username))]


def add_indicator(db, username, case_id, indicator_type, value, note=""):
    value = (value or "").strip()[:500]
    if not value or indicator_type not in INDICATOR_TYPES or not get_case(db, username, case_id):
        return False
    normalized = value.lower() if indicator_type in {"URL", "Domain", "Email", "File hash"} else value
    with _connect(db) as con:
        con.execute("INSERT OR IGNORE INTO cybercrime_indicators(case_id,username,indicator_type,value,normalized_value,note) "
                    "VALUES(?,?,?,?,?,?)", (int(case_id), username, indicator_type, value, normalized, (note or "")[:500]))
        con.execute("UPDATE cybercrime_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=? AND username=?",
                    (int(case_id), username))
    return True


def list_case_indicators(db, username, case_id):
    with _connect(db) as con:
        return [dict(row) for row in con.execute(
            "SELECT id,indicator_type,value,note,created_at FROM cybercrime_indicators "
            "WHERE case_id=? AND username=? ORDER BY indicator_type,value", (int(case_id), username))]


def related_case_indicators(db, username, case_id):
    with _connect(db) as con:
        return [dict(row) for row in con.execute(
            "SELECT i.indicator_type,i.value,i.note,c.id AS related_case_id,c.title AS related_case_title "
            "FROM cybercrime_indicators i JOIN cybercrime_indicators j "
            "ON i.username=j.username AND i.indicator_type=j.indicator_type AND i.normalized_value=j.normalized_value "
            "JOIN cybercrime_cases c ON c.id=j.case_id AND c.username=j.username "
            "WHERE i.case_id=? AND i.username=? AND j.case_id<>? ORDER BY i.indicator_type,c.id",
            (int(case_id), username, int(case_id)))]


def attach_scans(db, username, case_id, scan_ids):
    with _connect(db) as con:
        owned = con.execute("SELECT 1 FROM cybercrime_cases WHERE id=? AND username=?",
                            (int(case_id), username)).fetchone()
        if not owned:
            return False
        available = {r[0] for r in con.execute("SELECT id FROM scans WHERE username=?", (username,))}
        chosen = sorted({int(x) for x in scan_ids if int(x) in available})
        con.execute("DELETE FROM cybercrime_case_scans WHERE case_id=? AND username=?", (int(case_id), username))
        con.executemany("INSERT INTO cybercrime_case_scans(case_id,scan_id,username) VALUES(?,?,?)",
                        [(int(case_id), scan_id, username) for scan_id in chosen])
        scan_rows = con.execute("SELECT id,target,result FROM scans WHERE username=? AND id IN ({})".format(
            ",".join("?" for _ in chosen) or "NULL"), (username, *chosen)).fetchall()
    # Import indicators from scans into the case so exact cross-case matching
    # works without analysts retyping URLs, domains, addresses, or hashes.
    from services.extended_features import extract_iocs
    for scan_id, target, raw in scan_rows:
        try:
            parsed = ast.literal_eval(raw)
            serialized = json.dumps(parsed, ensure_ascii=False, default=str) + " " + str(target)
            extracted = extract_iocs(serialized)
        except Exception:
            continue
        for label, values in extracted.items():
            mapped_type = {"URLs": "URL", "Domains": "Domain", "IP addresses": "IP address",
                           "File hashes": "File hash"}.get(label)
            if mapped_type:
                for value in values:
                    add_indicator(db, username, case_id, mapped_type, value,
                                  f"Auto-linked from CyberSentinel scan #{scan_id}")
    return True


def list_case_scans(db, username, case_id):
    with _connect(db) as con:
        return [dict(row) for row in con.execute(
            "SELECT s.id,s.scan_type,s.target,s.score,s.created_at FROM scans s "
            "JOIN cybercrime_case_scans x ON x.scan_id=s.id AND x.username=s.username "
            "WHERE x.case_id=? AND x.username=? AND s.username=? ORDER BY s.id DESC",
            (int(case_id), username, username))]


def export_case_bundle(db, username, case_id, redact=False, include_originals=False):
    case = get_case(db, username, case_id)
    if not case:
        return None
    events = list_case_events(db, username, case_id)
    evidence = list_case_evidence(db, username, case_id)
    indicators = list_case_indicators(db, username, case_id)
    scans = list_case_scans(db, username, case_id)
    if redact:
        case["title"] = "[redacted]"
        case["description"] = "[redacted]"
        case["victim_contact"] = "[redacted]" if case["victim_contact"] else ""
        case["payment_details"] = "[redacted]" if case["payment_details"] else ""
        case["extortion_details"] = "[redacted]" if case["extortion_details"] else ""
        case.pop("username", None)
        for event in events:
            event["summary"] = "[redacted]"
        for indicator in indicators:
            indicator["value"] = "[redacted]"
            indicator["note"] = "[redacted]" if indicator["note"] else ""
        for scan in scans:
            scan["target"] = "[redacted]"
        include_originals = False

    manifest = []
    integrity_by_id = {}
    for evidence_item in evidence:
        path = _evidence_path(username, case_id, evidence_item["evidence_id"])
        integrity = "missing"
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            integrity = "match" if digest == evidence_item["sha256"] else "mismatch"
        integrity_by_id[evidence_item["evidence_id"]] = integrity
        manifest.append({k: evidence_item[k] for k in ("evidence_id", "filename", "evidence_type", "content_type", "size_bytes", "sha256", "created_at")}
                        | {"integrity_check": integrity})
    if redact:
        for index, item in enumerate(manifest, 1):
            item["filename"] = f"evidence-{index}"
    payload = {"case": case, "timeline": events, "indicators": indicators,
               "linked_scans": scans, "evidence_manifest": manifest,
               "exported_at": datetime.now().astimezone().isoformat(),
               "redacted": bool(redact),
               "note": "Indicators are investigative leads and do not establish attribution or criminal conduct."}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("case.json", json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        bundle.writestr("evidence_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        timeline_io = io.StringIO()
        writer = csv.DictWriter(timeline_io, fieldnames=["event_at", "summary", "created_at"])
        writer.writeheader()
        rows = []
        for event in events:
            row = {key: str(event.get(key, "")) for key in writer.fieldnames}
            for key, value in row.items():
                if value.startswith(("=", "+", "-", "@", "\t", "\r")):
                    row[key] = "'" + value
            rows.append(row)
        writer.writerows(rows)
        bundle.writestr("timeline.csv", timeline_io.getvalue())
        if include_originals:
            for evidence_item in evidence:
                path = _evidence_path(username, case_id, evidence_item["evidence_id"])
                if path.is_file() and integrity_by_id.get(evidence_item["evidence_id"]) == "match":
                    file_name = Path(evidence_item["filename"].replace("\\", "/")).name
                    bundle.write(path, f"original_evidence/{evidence_item['evidence_id']}/{file_name}")
    return buffer.getvalue()
