"""
Authentication & session management.

Upgrades over the original SHA-256-only implementation:
  - bcrypt (salted, adaptive-cost) password hashing instead of raw SHA-256.
  - Transparent migration: any legacy SHA-256 hash is re-hashed with bcrypt
    the next time that user logs in successfully.
  - Account lockout after repeated failed attempts (per-username, sliding
    window), to slow down brute-force/credential-stuffing attempts.
  - Password strength requirements on registration.
  - Server-side session tokens with idle expiry, so a UI layer (e.g.
    app.py) can enforce "log out after N minutes of inactivity" instead of
    trusting an indefinitely-alive in-memory session flag.
"""
import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

import bcrypt

FAILED_ATTEMPT_LIMIT = 5
LOCKOUT_WINDOW_MINUTES = 15
SESSION_IDLE_TIMEOUT_MINUTES = 30


def _hash_legacy_sha256(password: str) -> str:
    """Kept only to recognize/migrate hashes created by the old scheme."""
    return hashlib.sha256(password.encode()).hexdigest()


def _hash_bcrypt(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _looks_like_bcrypt(hash_str: str) -> bool:
    return hash_str.startswith(("$2a$", "$2b$", "$2y$"))


def _password_strength_error(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password):
        return "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    return None


def _production_password_error(password: str):
    if len(password) < 14:
        return "Administrator password must be at least 14 characters."
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return "Administrator password must include lowercase and uppercase letters."
    if not re.search(r"\d", password):
        return "Administrator password must include a number."
    if password.lower() in {"password123456", "changeme123456", "adminpassword1"}:
        return "Choose a unique administrator password."
    return None


def init_db(db):
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        scan_type TEXT,
        target TEXT,
        result TEXT,
        score REAL,
        created_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS login_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        success INTEGER,
        created_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        username TEXT,
        created_at TEXT,
        last_seen_at TEXT)""")
    environment = os.getenv("CYBERSENTINEL_ENV", "development").strip().lower()
    production = environment in {"production", "prod"}
    demo_flag = os.getenv("CYBERSENTINEL_DEMO_ADMIN")
    demo_enabled = (demo_flag.lower() in {"1", "true", "yes"}) if demo_flag is not None else not production
    if production:
        demo_enabled = False
    bootstrap_user = os.getenv("CYBERSENTINEL_ADMIN_USERNAME", "").strip()
    bootstrap_password = os.getenv("CYBERSENTINEL_ADMIN_PASSWORD", "")
    if production and (not bootstrap_user or not bootstrap_password):
        con.close()
        raise RuntimeError("Production requires CYBERSENTINEL_ADMIN_USERNAME and CYBERSENTINEL_ADMIN_PASSWORD.")
    if production and _production_password_error(bootstrap_password):
        con.close()
        raise RuntimeError(_production_password_error(bootstrap_password))

    # Demo credentials are available only in development, never in a hosted production mode.
    if demo_enabled and not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        # INSERT OR IGNORE closes the check-then-insert race when two app
        # processes initialize the same SQLite database at the same time.
        con.execute("INSERT OR IGNORE INTO users(username,password_hash) VALUES(?,?)",
                    ("admin", _hash_bcrypt("admin123")))
    if bootstrap_user and bootstrap_password:
        existing = con.execute("SELECT password_hash FROM users WHERE username=?", (bootstrap_user,)).fetchone()
        if existing:
            if production and bootstrap_user == "admin" and _looks_like_bcrypt(existing[0]) and bcrypt.checkpw(b"admin123", existing[0].encode()):
                con.execute("UPDATE users SET password_hash=? WHERE username=?", (_hash_bcrypt(bootstrap_password), bootstrap_user))
        else:
            con.execute("INSERT OR IGNORE INTO users(username,password_hash) VALUES(?,?)",
                        (bootstrap_user, _hash_bcrypt(bootstrap_password)))
    if production and bootstrap_user != "admin":
        demo_row = con.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()
        if demo_row and _looks_like_bcrypt(demo_row[0]) and bcrypt.checkpw(b"admin123", demo_row[0].encode()):
            con.execute("UPDATE users SET password_hash=? WHERE username='admin'", (_hash_bcrypt(secrets.token_urlsafe(32)),))
    con.commit()
    con.close()


def register_user(db, username, password):
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    strength_error = _password_strength_error(password)
    if strength_error:
        return False, strength_error
    con = sqlite3.connect(db)
    try:
        con.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                    (username, _hash_bcrypt(password)))
        con.commit()
        return True, "Account created."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        con.close()


def _record_attempt(con, username, success):
    con.execute("INSERT INTO login_attempts(username, success, created_at) VALUES(?,?,?)",
                (username, int(success), datetime.now().isoformat(timespec="seconds")))
    con.commit()


def _is_locked_out(con, username):
    cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat(timespec="seconds")
    row = con.execute(
        """SELECT COUNT(*) FROM login_attempts
           WHERE username=? AND success=0 AND created_at >= ?""",
        (username, cutoff)).fetchone()
    return (row[0] or 0) >= FAILED_ATTEMPT_LIMIT


def authenticate(db, username, password):
    """Returns (ok: bool, message: str). ok=False + message explains why
    (invalid credentials vs. locked out) so the UI can show something useful."""
    username = username.strip()
    con = sqlite3.connect(db)
    try:
        if _is_locked_out(con, username):
            return False, (f"Account temporarily locked after repeated failed attempts. "
                            f"Try again in {LOCKOUT_WINDOW_MINUTES} minutes.")

        row = con.execute("SELECT password_hash FROM users WHERE username=?",
                          (username,)).fetchone()
        if not row:
            _record_attempt(con, username, False)
            return False, "Invalid username or password."

        stored_hash = row[0]
        if _looks_like_bcrypt(stored_hash):
            ok = bcrypt.checkpw(password.encode(), stored_hash.encode())
        else:
            # Legacy SHA-256 hash: verify against old scheme, then migrate.
            ok = stored_hash == _hash_legacy_sha256(password)
            if ok:
                con.execute("UPDATE users SET password_hash=? WHERE username=?",
                            (_hash_bcrypt(password), username))
                con.commit()

        _record_attempt(con, username, ok)
        return (True, "OK") if ok else (False, "Invalid username or password.")
    finally:
        con.close()


def create_session(db, username):
    token = secrets.token_urlsafe(32)
    now = datetime.now().isoformat(timespec="seconds")
    con = sqlite3.connect(db)
    con.execute("INSERT INTO sessions(token, username, created_at, last_seen_at) VALUES(?,?,?,?)",
                (token, username, now, now))
    con.commit()
    con.close()
    return token


def validate_session(db, token):
    """Returns username if the session is valid and not idle-expired, else None.
    Touches last_seen_at on success (sliding expiry)."""
    if not token:
        return None
    con = sqlite3.connect(db)
    try:
        row = con.execute("SELECT username, last_seen_at FROM sessions WHERE token=?",
                          (token,)).fetchone()
        if not row:
            return None
        username, last_seen_at = row
        cutoff = datetime.now() - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
        if datetime.fromisoformat(last_seen_at) < cutoff:
            con.execute("DELETE FROM sessions WHERE token=?", (token,))
            con.commit()
            return None
        con.execute("UPDATE sessions SET last_seen_at=? WHERE token=?",
                    (datetime.now().isoformat(timespec="seconds"), token))
        con.commit()
        return username
    finally:
        con.close()


def invalidate_session(db, token):
    con = sqlite3.connect(db)
    con.execute("DELETE FROM sessions WHERE token=?", (token,))
    con.commit()
    con.close()
