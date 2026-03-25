"""
QCI Notification Engine — single-file Flask application
"""
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
import smtplib
import psycopg2
import psycopg2.extras
import struct
import threading
import time
import urllib.request
from datetime import date, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from flask import (Flask, flash, jsonify, redirect, render_template_string,
                   request, url_for, Response, session)
from werkzeug.security import check_password_hash as _check_pw

def generate_password_hash(pw):
    from werkzeug.security import generate_password_hash as _gph
    return _gph(pw, method="pbkdf2:sha256")

def check_password_hash(hsh, pw):
    return _check_pw(hsh, pw)

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    HAS_XLSX = True
except ImportError:
    HAS_XLSX = False

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)

# Stable secret key persisted to disk
_SK_FILE = os.path.join(os.path.dirname(__file__), "secret.key")
if os.path.exists(_SK_FILE):
    with open(_SK_FILE) as _f:
        _SK = _f.read().strip()
else:
    _SK = secrets.token_hex(32)
    with open(_SK_FILE, "w") as _f:
        _f.write(_SK)
app.secret_key = os.environ.get("SECRET_KEY", _SK)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
KEY_FILE = os.path.join(os.path.dirname(__file__), "fernet.key")

# ── Fernet encryption ────────────────────────────────────────────────────────
_fk_env = os.environ.get("FERNET_KEY")
if _fk_env:
    _FERNET_KEY = _fk_env.encode()
elif os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as _f:
        _FERNET_KEY = _f.read()
else:
    _FERNET_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as _f:
        _f.write(_FERNET_KEY)

_fernet = Fernet(_FERNET_KEY)


def encrypt_str(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def decrypt_str(text: str) -> str:
    try:
        return _fernet.decrypt(text.encode()).decode()
    except Exception:
        return ""


def get_app_setting(key: str, default: str = "") -> str:
    conn = get_db()
    row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def set_app_setting(key: str, value: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value)
    )
    conn.commit()
    conn.close()


def log_audit(event_type: str, application_id: str = None, detail: str = "",
              user_name: str = None, board_id: int = None):
    """Write a row to the audit_log table."""
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (timestamp, application_id, event_type, detail, user_name, board_id) "
        "VALUES (?,?,?,?,?,?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), application_id, event_type,
         detail[:500] if detail else "", user_name, board_id)
    )
    conn.commit()
    conn.close()


def log_stage_transition(application_id: str, from_stage: str, to_stage: str,
                         changed_by: str = None, board_id: int = None):
    """Record a stage transition in stage_history."""
    conn = get_db()
    conn.execute(
        "INSERT INTO stage_history (timestamp, application_id, from_stage, to_stage, changed_by, board_id) "
        "VALUES (?,?,?,?,?,?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), application_id, from_stage, to_stage,
         changed_by, board_id)
    )
    conn.commit()
    conn.close()


# ── TOTP (software 2FA — no external library needed) ─────────────────────────
def _hotp(key_bytes: bytes, counter: int) -> int:
    msg = struct.pack(">Q", counter)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    return ((h[offset] & 0x7F) << 24 | h[offset+1] << 16 |
            h[offset+2] << 8 | h[offset+3]) % 1_000_000


def totp_now(base32_secret: str) -> str:
    import base64
    try:
        key = base64.b32decode(base32_secret.upper() + "=" * (-len(base32_secret) % 8))
        return f"{_hotp(key, int(time.time()) // 30):06d}"
    except Exception:
        return "000000"


def totp_verify(base32_secret: str, code: str, window: int = 1) -> bool:
    import base64
    try:
        key = base64.b32decode(base32_secret.upper() + "=" * (-len(base32_secret) % 8))
        t = int(time.time()) // 30
        for delta in range(-window, window + 1):
            if f"{_hotp(key, t + delta):06d}" == code.strip():
                return True
        return False
    except Exception:
        return False


def totp_generate_secret() -> str:
    import base64
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_provisioning_uri(secret: str, username: str) -> str:
    import urllib.parse
    padded = secret + "=" * (-len(secret) % 8)
    params = urllib.parse.urlencode({"secret": padded, "issuer": "QCI Engine"})
    return f"otpauth://totp/QCI%20Engine:{urllib.parse.quote(username)}?{params}"


# ── Email queue helpers ───────────────────────────────────────────────────────
def queue_email(programme_name: str, notification_type: str, to_email: str,
                cc_email: str, sender_email: str, sender_password_enc: str,
                ph: dict, smtp_host: str, smtp_port: int,
                application_id: str = None, board_id: int = None):
    """Resolve template + placeholders and add to email_queue."""
    conn = get_db()
    tmpl = conn.execute(
        "SELECT subject_line, email_body FROM email_templates "
        "WHERE programme_name=? AND notification_type=?",
        (programme_name, notification_type)
    ).fetchone()
    if not tmpl:
        conn.close()
        return
    subj, body = tmpl["subject_line"], tmpl["email_body"]
    for k, v in ph.items():
        subj = subj.replace("{{" + k + "}}", str(v))
        body = body.replace("{{" + k + "}}", str(v))
    conn.execute(
        """INSERT INTO email_queue
           (queued_at, application_id, programme_name, notification_type,
            to_email, cc_email, sender_email, sender_password, smtp_host, smtp_port,
            subject, body, status, board_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',?)""",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), application_id, programme_name,
         notification_type, to_email, cc_email or "", sender_email, sender_password_enc,
         smtp_host, smtp_port, subj, body, board_id)
    )
    conn.commit()
    conn.close()


def process_email_queue(max_retries: int = 3) -> dict:
    """Process pending email_queue items. Returns counts."""
    conn = get_db()
    pending = [dict(r) for r in conn.execute(
        "SELECT * FROM email_queue WHERE status='pending' AND attempts < ?", (max_retries,)
    ).fetchall()]
    sent = failed = 0
    for item in pending:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = item["subject"] or ""
            msg["From"] = item["sender_email"]
            msg["To"] = item["to_email"]
            recipients = [item["to_email"]]
            if item.get("cc_email"):
                for cc in item["cc_email"].split(","):
                    cc = cc.strip()
                    if cc:
                        msg["Cc"] = cc
                        recipients.append(cc)
            msg.attach(MIMEText(item["body"] or "", "plain"))
            pw = decrypt_str(item["sender_password"]) if item.get("sender_password") else ""
            with smtplib.SMTP(item["smtp_host"], item["smtp_port"], timeout=15) as s:
                s.starttls()
                s.login(item["sender_email"], pw)
                s.sendmail(item["sender_email"], recipients, msg.as_string())
            conn.execute(
                "UPDATE email_queue SET status='sent', last_attempt=? WHERE id=?",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), item["id"])
            )
            sent += 1
        except Exception as e:
            attempts = item["attempts"] + 1
            new_status = "failed" if attempts >= max_retries else "pending"
            conn.execute(
                "UPDATE email_queue SET status=?, attempts=?, last_attempt=?, error_msg=? WHERE id=?",
                (new_status, attempts, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 str(e)[:300], item["id"])
            )
            failed += 1
    conn.commit()
    conn.close()
    return {"sent": sent, "failed": failed}


def fire_webhook(event_type: str, payload: dict):
    """Fire outbound webhook (WhatsApp/SMS stub). Non-blocking, swallows errors."""
    url = get_app_setting("webhook_url", "").strip()
    if not url:
        return
    try:
        data = json.dumps({"event": event_type, "data": payload}).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log.warning("Webhook fire failed: %s", e)


# ── Indian public holidays (2025–2027) ──────────────────────────────────────
_HOLIDAYS = {
    date(2025, 1, 26), date(2025, 3, 17), date(2025, 4, 14), date(2025, 4, 18),
    date(2025, 5, 12), date(2025, 8, 15), date(2025, 10, 2), date(2025, 10, 20),
    date(2025, 11, 5), date(2025, 11, 15), date(2025, 12, 25),
    date(2026, 1, 26), date(2026, 3, 6),  date(2026, 4, 3),  date(2026, 4, 14),
    date(2026, 5, 1),  date(2026, 8, 15), date(2026, 10, 2), date(2026, 10, 9),
    date(2026, 11, 25), date(2026, 12, 25),
    date(2027, 1, 26), date(2027, 3, 25), date(2027, 4, 2),  date(2027, 4, 14),
    date(2027, 8, 15), date(2027, 10, 2), date(2027, 12, 25),
}


def working_days_elapsed(start: str, end_d=None, hold_days: int = 0) -> int:
    """Working days from start (inclusive) to end (inclusive, default today).

    hold_days: subtract paused/on-hold days from the elapsed count.
    start strings longer than 10 chars (e.g. Excel datetime exports) are
    truncated to the date portion before parsing.
    """
    if end_d is None:
        end_d = date.today()
    if not start:
        return 0
    try:
        if isinstance(start, str):
            start = start[:10]  # trim Excel datetime suffix e.g. "2024-01-15 00:00:00"
        s = datetime.strptime(start, "%Y-%m-%d").date() if isinstance(start, str) else start
    except (ValueError, TypeError):
        return 0
    count = 0
    cur = s
    while cur <= end_d:
        if cur.weekday() < 5 and cur not in _HOLIDAYS:
            count += 1
        cur += timedelta(days=1)
    return max(0, count - 1 - hold_days)  # days elapsed after start date, minus hold days


# ── Database helpers ─────────────────────────────────────────────────────────
class DBConn:
    """Thin psycopg2 wrapper that mimics the sqlite3 connection API used throughout this app.

    Handles:
    - ``?`` → ``%s`` placeholder translation
    - ``INTEGER PRIMARY KEY AUTOINCREMENT`` → ``SERIAL PRIMARY KEY`` in DDL
    - ``executescript()`` by splitting on ``;`` and executing each statement
    - sqlite3-style ``conn.execute()`` that returns the cursor
    """

    def __init__(self, pg_conn):
        self._conn = pg_conn
        self._cur = pg_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    def execute(self, sql, params=()):
        pg_sql = sql.replace("?", "%s")
        if params:
            self._cur.execute(pg_sql, params)
        else:
            self._cur.execute(pg_sql)
        return self._cur

    def executescript(self, sql):
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            pg_stmt = (
                stmt
                .replace("?", "%s")
                .replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
            )
            self._cur.execute(pg_stmt)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Add a PostgreSQL plugin in your Railway project and set DATABASE_URL."
        )
    pg_conn = psycopg2.connect(DATABASE_URL)
    pg_conn.autocommit = False
    return DBConn(pg_conn)


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS boards (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            board_name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS programmes (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            programme_name TEXT NOT NULL UNIQUE,
            board_id       INTEGER NOT NULL REFERENCES boards(id)
        );
        CREATE TABLE IF NOT EXISTS programme_config (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            programme_name       TEXT NOT NULL,
            stage_name           TEXT NOT NULL,
            stage_order          INTEGER NOT NULL DEFAULT 0,
            tat_days             INTEGER NOT NULL DEFAULT 0,
            reminder1_day        INTEGER NOT NULL DEFAULT 0,
            reminder2_day        INTEGER NOT NULL DEFAULT 0,
            owner_type           TEXT,
            overdue_interval_days INTEGER NOT NULL DEFAULT 3,
            is_milestone         INTEGER NOT NULL DEFAULT 0,
            sender_email         TEXT,
            sender_password      TEXT,
            smtp_host            TEXT NOT NULL DEFAULT 'smtp.gmail.com',
            smtp_port            INTEGER NOT NULL DEFAULT 587
        );
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'program_officer',
            full_name     TEXT,
            email         TEXT
        );
        CREATE TABLE IF NOT EXISTS case_tracking (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id       TEXT NOT NULL UNIQUE,
            programme_name       TEXT NOT NULL,
            organisation_name    TEXT NOT NULL,
            current_stage        TEXT NOT NULL,
            stage_start_date     TEXT NOT NULL,
            tat_days             INTEGER NOT NULL DEFAULT 0,
            reminder1_day        INTEGER NOT NULL DEFAULT 0,
            reminder2_day        INTEGER NOT NULL DEFAULT 0,
            owner_type           TEXT,
            action_owner_name    TEXT,
            action_owner_email   TEXT,
            program_officer_email TEXT,
            r1_sent              INTEGER NOT NULL DEFAULT 0,
            r2_sent              INTEGER NOT NULL DEFAULT 0,
            overdue_sent         INTEGER NOT NULL DEFAULT 0,
            overdue_count        INTEGER NOT NULL DEFAULT 0,
            last_overdue_date    TEXT,
            is_milestone         INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS email_templates (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            programme_name    TEXT NOT NULL,
            notification_type TEXT NOT NULL,
            subject_line      TEXT NOT NULL,
            email_body        TEXT NOT NULL,
            UNIQUE(programme_name, notification_type)
        );
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            application_id  TEXT,
            event_type      TEXT NOT NULL,
            detail          TEXT,
            user_name       TEXT,
            board_id        INTEGER
        );
        CREATE TABLE IF NOT EXISTS stage_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            application_id  TEXT NOT NULL,
            from_stage      TEXT,
            to_stage        TEXT NOT NULL,
            changed_by      TEXT,
            board_id        INTEGER
        );
        CREATE TABLE IF NOT EXISTS email_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            queued_at       TEXT NOT NULL,
            application_id  TEXT,
            programme_name  TEXT,
            notification_type TEXT NOT NULL,
            to_email        TEXT NOT NULL,
            cc_email        TEXT,
            sender_email    TEXT,
            sender_password TEXT,
            smtp_host       TEXT NOT NULL DEFAULT 'smtp.gmail.com',
            smtp_port       INTEGER NOT NULL DEFAULT 587,
            subject         TEXT,
            body            TEXT,
            status          TEXT NOT NULL DEFAULT 'pending',
            attempts        INTEGER NOT NULL DEFAULT 0,
            last_attempt    TEXT,
            error_msg       TEXT,
            board_id        INTEGER
        );
        CREATE TABLE IF NOT EXISTS scheduler_locks (
            lock_name       TEXT PRIMARY KEY,
            locked_at       TEXT NOT NULL,
            worker_id       TEXT NOT NULL
        );
    """)
    # Migrate existing DBs: add columns if absent (IF NOT EXISTS is safe to re-run)
    for sql in [
        "ALTER TABLE programme_config ADD COLUMN IF NOT EXISTS smtp_host TEXT NOT NULL DEFAULT 'smtp.gmail.com'",
        "ALTER TABLE programme_config ADD COLUMN IF NOT EXISTS smtp_port INTEGER NOT NULL DEFAULT 587",
        "ALTER TABLE programme_config ADD COLUMN IF NOT EXISTS board_id INTEGER",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS board_id INTEGER",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_reset INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT",
        "ALTER TABLE case_tracking ADD COLUMN IF NOT EXISTS board_id INTEGER",
        "ALTER TABLE case_tracking ADD COLUMN IF NOT EXISTS cc_emails TEXT",
        "ALTER TABLE case_tracking ADD COLUMN IF NOT EXISTS suppress_until TEXT",
        "ALTER TABLE email_templates ADD COLUMN IF NOT EXISTS board_id INTEGER",
    ]:
        try:
            conn.execute(sql)
        except Exception:
            conn.rollback()
    conn.commit()
    conn.close()


# ── Auth helpers ──────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        if session.get("role") != "super_admin":
            flash("This page requires Super Admin access.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


def board_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        if session.get("role") not in ("super_admin", "board_admin"):
            flash("This page requires Board Admin access.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Seed data ────────────────────────────────────────────────────────────────
_SEED_STAGES = [
    ("NABH Full Accreditation Hospitals", "Application In Progress", 1, 30, 15, 25, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "Application Fee Pending", 2, 10, 5, 8, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "Application Fee Paid", 3, 0, 0, 0, None, 0, 1),
    ("NABH Full Accreditation Hospitals", "DR Allocated", 4, 3, 1, 2, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "DR In Progress", 5, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "DR NC Response", 6, 20, 10, 15, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "DR NC Review", 7, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "DR Approval by NABH", 8, 3, 1, 2, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "Assessment selection (if applicable)", 9, 5, 2, 4, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "PA Allocation", 10, 20, 10, 15, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "PA date Accepted by Assessor", 11, 7, 3, 5, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "PA Scheduled", 12, 5, 2, 4, "Applicant", 1, 0),
    ("NABH Full Accreditation Hospitals", "PA completed", 13, 3, 1, 2, "Assessor", 1, 0),
    ("NABH Full Accreditation Hospitals", "PA Feedback", 14, 2, 1, 999, "Applicant", 1, 0),
    ("NABH Full Accreditation Hospitals", "PA NC Response 1", 15, 50, 30, 40, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "PA NC Review 1", 16, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "PA NC Response 2", 17, 30, 10, 20, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "PA NC Review 2", 18, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "1st Annual Fee Pending", 19, 10, 5, 8, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "1st Annual Fee Paid", 20, 0, 0, 0, None, 0, 1),
    ("NABH Full Accreditation Hospitals", "OA Allocated", 21, 20, 10, 15, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "OA date Accepted by Assessor", 22, 7, 3, 5, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "OA Scheduled", 23, 5, 3, 4, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "OA completed", 24, 3, 1, 2, "Assessor", 2, 0),
    ("NABH Full Accreditation Hospitals", "OA Feedback", 25, 2, 1, 999, "Applicant", 1, 0),
    ("NABH Full Accreditation Hospitals", "OA NC Response 1", 26, 50, 30, 40, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "OA NC Review 1", 27, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "OA NC Response 2", 28, 30, 10, 20, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "OA NC Review 2", 29, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "OA NC Accepted", 30, 0, 0, 0, None, 0, 1),
    ("NABH Full Accreditation Hospitals", "AC Allocated", 31, 15, 7, 10, "Program Officer", 2, 0),
    ("NABH Full Accreditation Hospitals", "AC Document Pending", 32, 90, 30, 60, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "Pending Document Submitted", 33, 0, 0, 0, None, 0, 1),
    ("NABH Full Accreditation Hospitals", "Accredited/ Accredited Renewed", 34, 30, 15, 20, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "2nd Annual Fee Payment", 35, 90, 1, 10, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "2nd Annual Fee Paid", 36, 0, 0, 0, None, 0, 1),
    ("NABH Full Accreditation Hospitals", "SA due", 37, 30, 15, 20, "Program Officer", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA Allocated", 38, 20, 10, 15, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA date Accepted by Assessor", 39, 7, 3, 5, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA Scheduled", 40, 5, 3, 4, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA completed", 41, 3, 1, 2, "Assessor", 2, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA Feedback", 42, 2, 1, 999, "Applicant", 1, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA NC Response 1", 43, 25, 15, 20, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA NC Review 1", 44, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA NC Response 2", 45, 15, 7, 10, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA NC Review 2", 46, 10, 5, 7, "Assessor", 3, 0),
    ("NABH Full Accreditation Hospitals", "SA - OA NC Accepted", 47, 0, 0, 0, None, 0, 1),
    ("NABH Full Accreditation Hospitals", "SA - AC Allocated", 48, 15, 7, 10, "Program Officer", 2, 0),
    ("NABH Full Accreditation Hospitals", "Accredited Continued", 49, 30, 15, 20, "Program Officer", 1, 0),
    ("NABH Full Accreditation Hospitals", "3rd Annual Fee Payment", 50, 90, 1, 10, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "4th Annual Fee Payment", 51, 90, 1, 10, "Applicant", 3, 0),
    ("NABH Full Accreditation Hospitals", "Renewal", 52, 90, 30, 60, "Applicant", 3, 0),
]

_SEED_TEMPLATES = [
    ("NABH Full Accreditation Hospitals", "R1",
     "Reminder: {{Stage_Name}} action pending — {{Organisation_Name}}",
     "Dear {{Action_Owner_Name}},\n\nThis is a reminder that your action on the stage '{{Stage_Name}}' "
     "under the {{Programme_Name}} programme is pending.\n\nCase: {{Organisation_Name}}\n"
     "Stage start date: {{Stage_Start_Date}}\nDeadline: {{TAT_Days}} working days from stage start\n"
     "Days remaining: {{Days_Remaining}}\n\nPlease log in to the portal and complete the required action "
     "at your earliest convenience.\n\nRegards,\n{{PO_Name}}\nQuality Council of India"),
    ("NABH Full Accreditation Hospitals", "R2",
     "Action Required: {{Stage_Name}} deadline approaching — {{Organisation_Name}}",
     "Dear {{Action_Owner_Name}},\n\nThe deadline for '{{Stage_Name}}' under {{Programme_Name}} is approaching.\n\n"
     "Case: {{Organisation_Name}}\nDays remaining: {{Days_Remaining}}\n\n"
     "Immediate action is required to avoid a breach of TAT. Please log in to the portal and complete the required action.\n\n"
     "Regards,\n{{PO_Name}}\nQuality Council of India"),
    ("NABH Full Accreditation Hospitals", "Overdue",
     "OVERDUE: {{Stage_Name}} TAT breached — {{Organisation_Name}}",
     "Dear {{Action_Owner_Name}},\n\nThe TAT for '{{Stage_Name}}' under {{Programme_Name}} has been breached.\n\n"
     "Case: {{Organisation_Name}}\nStage start date: {{Stage_Start_Date}}\nTAT: {{TAT_Days}} working days\n\n"
     "This is an urgent matter. Please take immediate action on the portal.\n\n"
     "Regards,\n{{PO_Name}}\nQuality Council of India"),
    ("NABH Full Accreditation Hospitals", "Followup",
     "Follow-up {{Followup_Count}}: {{Stage_Name}} still pending — {{Organisation_Name}}",
     "Dear {{Action_Owner_Name}},\n\nThis is follow-up #{{Followup_Count}} regarding the overdue stage "
     "'{{Stage_Name}}' under {{Programme_Name}}.\n\nCase: {{Organisation_Name}}\n\n"
     "This stage has been overdue. Please take immediate action.\n\n"
     "Regards,\n{{PO_Name}}\nQuality Council of India"),
]


_SEED_BOARDS = ["NABH", "NABL", "NABCB", "NABET"]


def migrate_data():
    """One-time migration: seeds boards, backfills board_id, renames admin→super_admin."""
    conn = get_db()
    # 1. Seed boards
    for b in _SEED_BOARDS:
        try:
            conn.execute("INSERT INTO boards (board_name) VALUES (?)", (b,))
        except Exception:
            pass
    conn.commit()

    # 2. Rename role admin → super_admin
    conn.execute("UPDATE users SET role='super_admin' WHERE role='admin'")
    conn.commit()

    # 3. Backfill programmes table from programme_config
    distinct_progs = conn.execute(
        "SELECT DISTINCT programme_name FROM programme_config"
    ).fetchall()
    for row in distinct_progs:
        pname = row[0]
        # Already in programmes table? Skip.
        if conn.execute("SELECT id FROM programmes WHERE programme_name=?", (pname,)).fetchone():
            continue
        # Infer board by prefix
        board_row = None
        for b in _SEED_BOARDS:
            if pname.upper().startswith(b):
                board_row = conn.execute("SELECT id FROM boards WHERE board_name=?", (b,)).fetchone()
                break
        if not board_row:
            board_row = conn.execute("SELECT id FROM boards ORDER BY id LIMIT 1").fetchone()
        if board_row:
            try:
                conn.execute("INSERT INTO programmes (programme_name, board_id) VALUES (?,?)",
                             (pname, board_row[0]))
            except Exception:
                pass
    conn.commit()

    # 4. Backfill board_id on programme_config
    conn.execute("""
        UPDATE programme_config SET board_id = (
            SELECT board_id FROM programmes WHERE programmes.programme_name = programme_config.programme_name
        ) WHERE board_id IS NULL
    """)
    conn.commit()

    # 5. Backfill board_id on case_tracking
    conn.execute("""
        UPDATE case_tracking SET board_id = (
            SELECT board_id FROM programme_config
            WHERE programme_config.programme_name = case_tracking.programme_name LIMIT 1
        ) WHERE board_id IS NULL
    """)
    conn.commit()

    # 6. Backfill board_id on email_templates
    conn.execute("""
        UPDATE email_templates SET board_id = (
            SELECT board_id FROM programmes
            WHERE programmes.programme_name = email_templates.programme_name
        ) WHERE board_id IS NULL
    """)
    conn.commit()

    # 7. Default officer user → NABH board if no board assigned
    nabh = conn.execute("SELECT id FROM boards WHERE board_name='NABH'").fetchone()
    if nabh:
        conn.execute(
            "UPDATE users SET board_id=? WHERE role='program_officer' AND board_id IS NULL",
            (nabh[0],)
        )
    conn.commit()
    conn.close()


def seed_data():
    conn = get_db()
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, full_name) VALUES (?,?,?,?)",
            ("admin", generate_password_hash("admin123"), "super_admin", "Super Administrator"),
        )
        nabh = conn.execute("SELECT id FROM boards WHERE board_name='NABH'").fetchone()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, full_name, board_id) VALUES (?,?,?,?,?)",
            ("officer", generate_password_hash("po123"), "program_officer", "Program Officer",
             nabh[0] if nabh else None),
        )
    if conn.execute("SELECT COUNT(*) FROM programme_config").fetchone()[0] == 0:
        nabh = conn.execute("SELECT id FROM boards WHERE board_name='NABH'").fetchone()
        nabh_id = nabh[0] if nabh else None
        # Insert programme record
        try:
            conn.execute("INSERT INTO programmes (programme_name, board_id) VALUES (?,?)",
                         ("NABH Full Accreditation Hospitals", nabh_id))
        except Exception:
            pass
        for row in _SEED_STAGES:
            conn.execute(
                "INSERT INTO programme_config "
                "(programme_name,stage_name,stage_order,tat_days,reminder1_day,reminder2_day,"
                "owner_type,overdue_interval_days,is_milestone,board_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*row, nabh_id),
            )
    if conn.execute("SELECT COUNT(*) FROM email_templates").fetchone()[0] == 0:
        nabh = conn.execute("SELECT id FROM boards WHERE board_name='NABH'").fetchone()
        nabh_id = nabh[0] if nabh else None
        for row in _SEED_TEMPLATES:
            conn.execute(
                "INSERT INTO email_templates (programme_name,notification_type,subject_line,email_body,board_id) VALUES (?,?,?,?,?)",
                (*row, nabh_id),
            )
    conn.commit()
    conn.close()


# ── Board scoping helper ──────────────────────────────────────────────────────
def user_board_id():
    """Returns board_id from session, or None for super_admin (sees all)."""
    if session.get("role") == "super_admin":
        return None
    return session.get("board_id")


# ── Email helpers ─────────────────────────────────────────────────────────────
_DEFAULT_SUBJECTS = {
    "R1":      "Reminder: {{Stage_Name}} action pending — {{Organisation_Name}}",
    "R2":      "Action Required: {{Stage_Name}} deadline approaching — {{Organisation_Name}}",
    "Overdue": "OVERDUE: {{Stage_Name}} TAT breached — {{Organisation_Name}}",
    "Followup":"Follow-up {{Followup_Count}}: {{Stage_Name}} still pending — {{Organisation_Name}}",
}
_DEFAULT_BODIES = {
    "R1":      "Dear {{Action_Owner_Name}},\n\nReminder for stage {{Stage_Name}} under {{Programme_Name}}.\nOrg: {{Organisation_Name}}\nDays remaining: {{Days_Remaining}}\n\nRegards,\n{{PO_Name}}\nQCI",
    "R2":      "Dear {{Action_Owner_Name}},\n\nDeadline approaching for {{Stage_Name}}.\nOrg: {{Organisation_Name}}\nDays remaining: {{Days_Remaining}}\n\nRegards,\n{{PO_Name}}\nQCI",
    "Overdue": "Dear {{Action_Owner_Name}},\n\nTAT breached for {{Stage_Name}}.\nOrg: {{Organisation_Name}}\n\nRegards,\n{{PO_Name}}\nQCI",
    "Followup":"Dear {{Action_Owner_Name}},\n\nFollow-up #{{Followup_Count}} for overdue stage {{Stage_Name}}.\nOrg: {{Organisation_Name}}\n\nRegards,\n{{PO_Name}}\nQCI",
}


def _fill(text: str, ph: dict) -> str:
    for k, v in ph.items():
        text = text.replace("{{" + k + "}}", str(v) if v is not None else "")
    return text


def _get_template(programme: str, ntype: str):
    conn = get_db()
    row = conn.execute(
        "SELECT subject_line, email_body FROM email_templates WHERE programme_name=? AND notification_type=?",
        (programme, ntype),
    ).fetchone()
    conn.close()
    return row


def send_notification(programme: str, ntype: str, to_email: str, cc_email: str,
                      sender_email: str, sender_password: str, ph: dict,
                      smtp_host: str = "smtp.gmail.com", smtp_port: int = 587):
    tmpl = _get_template(programme, ntype)
    subject = _fill(tmpl["subject_line"] if tmpl else _DEFAULT_SUBJECTS[ntype], ph)
    body    = _fill(tmpl["email_body"]    if tmpl else _DEFAULT_BODIES[ntype],    ph)

    if not sender_email or not to_email:
        return False, "Missing sender or recipient email"
    try:
        msg = MIMEMultipart()
        msg["From"]    = sender_email
        msg["To"]      = to_email
        msg["CC"]      = cc_email or ""
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        recipients = [to_email] + ([cc_email] if cc_email else [])
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, 465, timeout=15) as s:
                s.login(sender_email, sender_password)
                s.sendmail(sender_email, recipients, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
                s.starttls()
                s.login(sender_email, sender_password)
                s.sendmail(sender_email, recipients, msg.as_string())
        log_audit("email_sent", ph.get("Programme_Name", ""),
                  f"{ntype} to {to_email} | Subject: {subject[:80]}", "system")
        return True, ""
    except Exception as e:
        log_audit("email_error", ph.get("Programme_Name", ""),
                  f"{ntype} to {to_email} | Error: {str(e)[:200]}", "system")
        return False, str(e)


# ── Core daily check ─────────────────────────────────────────────────────────
def run_daily_check() -> dict:
    today = date.today()
    conn  = get_db()
    cases = [dict(r) for r in conn.execute("SELECT * FROM case_tracking").fetchall()]
    summary = {"r1": 0, "r2": 0, "overdue": 0, "followup": 0,
               "skipped_milestone": 0, "errors": []}

    for case in cases:
        if case["is_milestone"]:
            summary["skipped_milestone"] += 1
            continue

        elapsed = working_days_elapsed(case["stage_start_date"], today)
        tat     = case["tat_days"]
        r1_day  = case["reminder1_day"]
        r2_day  = case["reminder2_day"]

        cfg = conn.execute(
            "SELECT overdue_interval_days, sender_email, sender_password, smtp_host, smtp_port "
            "FROM programme_config WHERE programme_name=? AND stage_name=?",
            (case["programme_name"], case["current_stage"]),
        ).fetchone()

        overdue_interval = cfg["overdue_interval_days"] if cfg else 3
        sender_email     = cfg["sender_email"] if cfg and cfg["sender_email"] else None
        sender_password  = decrypt_str(cfg["sender_password"]) if cfg and cfg["sender_password"] else ""
        smtp_host        = cfg["smtp_host"] if cfg and cfg["smtp_host"] else "smtp.gmail.com"
        smtp_port        = cfg["smtp_port"] if cfg and cfg["smtp_port"] else 587

        days_remaining = max(0, tat - elapsed)
        ph = {
            "Organisation_Name": case["organisation_name"],
            "Stage_Name":        case["current_stage"],
            "Action_Owner_Name": case["action_owner_name"],
            "Days_Remaining":    days_remaining,
            "TAT_Days":          tat,
            "Stage_Start_Date":  case["stage_start_date"],
            "Programme_Name":    case["programme_name"],
            "Followup_Count":    case["overdue_count"] + 1,
            "PO_Name":           case["program_officer_email"] or "Program Officer",
        }

        # Check suppress_until
        suppress = case.get("suppress_until")
        if suppress:
            try:
                if date.fromisoformat(suppress) >= today:
                    continue
            except ValueError:
                pass

        sender_pw_enc = cfg["sender_password"] if cfg and cfg["sender_password"] else ""
        cc = case.get("cc_emails") or case.get("program_officer_email") or ""
        webhook_ph = {
            "application_id": case["application_id"],
            "organisation": case["organisation_name"],
            "programme": case["programme_name"],
            "stage": case["current_stage"],
        }

        def _send(ntype):
            if not sender_email or not case.get("action_owner_email"):
                summary["errors"].append(f"{case['application_id']} {ntype}: missing sender/recipient")
                return False
            queue_email(
                case["programme_name"], ntype,
                case["action_owner_email"], cc,
                sender_email, sender_pw_enc, ph,
                smtp_host, smtp_port,
                case["application_id"], case.get("board_id")
            )
            fire_webhook(f"notification_{ntype.lower()}", {**webhook_ph, "type": ntype})
            return True

        # R1
        if r1_day > 0 and elapsed >= r1_day and not case["r1_sent"]:
            _send("R1")
            conn.execute("UPDATE case_tracking SET r1_sent=1 WHERE id=?", (case["id"],))
            conn.commit()
            summary["r1"] += 1

        # R2
        if r2_day > 0 and elapsed >= r2_day and not case["r2_sent"]:
            _send("R2")
            conn.execute("UPDATE case_tracking SET r2_sent=1 WHERE id=?", (case["id"],))
            conn.commit()
            summary["r2"] += 1

        # First overdue
        if tat > 0 and elapsed >= tat and not case["overdue_sent"]:
            _send("OVERDUE")
            conn.execute(
                "UPDATE case_tracking SET overdue_sent=1, last_overdue_date=? WHERE id=?",
                (today.isoformat(), case["id"]),
            )
            conn.commit()
            summary["overdue"] += 1

        # Followup overdue
        elif tat > 0 and elapsed > tat and case["overdue_sent"] and case["last_overdue_date"]:
            last = datetime.strptime(case["last_overdue_date"], "%Y-%m-%d").date()
            if (today - last).days >= overdue_interval:
                ph["Followup_Count"] = case["overdue_count"] + 1
                _send("FOLLOWUP")
                conn.execute(
                    "UPDATE case_tracking SET overdue_count=overdue_count+1, last_overdue_date=? WHERE id=?",
                    (today.isoformat(), case["id"]),
                )
                conn.commit()
                summary["followup"] += 1

    conn.close()
    # Process queued emails
    q_result = process_email_queue()
    summary["emails_sent"] = q_result["sent"]
    summary["email_failures"] = q_result["failed"]
    return summary


# ── Case upsert helper ───────────────────────────────────────────────────────
def upsert_case(data: dict) -> str:
    """Insert or update a case. Returns 'created' or 'updated'."""
    conn = get_db()
    try:
        cfg = conn.execute(
            "SELECT tat_days,reminder1_day,reminder2_day,owner_type,is_milestone,overdue_interval_days,board_id "
            "FROM programme_config WHERE programme_name=? AND stage_name=?",
            (data["programme_name"], data["stage_name"]),
        ).fetchone()
        if not cfg:
            raise ValueError(f"Stage '{data['stage_name']}' not found in programme '{data['programme_name']}'")

        existing = conn.execute(
            "SELECT id, current_stage FROM case_tracking WHERE application_id=?", (data["application_id"],)
        ).fetchone()

        board_id = cfg["board_id"]
        if existing:
            old_stage = existing["current_stage"]
            new_stage = data["stage_name"]
            conn.execute(
                """UPDATE case_tracking SET
                   programme_name=?, organisation_name=?, current_stage=?, stage_start_date=?,
                   tat_days=?, reminder1_day=?, reminder2_day=?, owner_type=?,
                   action_owner_name=?, action_owner_email=?, program_officer_email=?,
                   r1_sent=0, r2_sent=0, overdue_sent=0, overdue_count=0,
                   last_overdue_date=NULL, is_milestone=?, board_id=?,
                   cc_emails=?, suppress_until=?
                   WHERE application_id=?""",
                (data["programme_name"], data["organisation_name"], data["stage_name"],
                 data["stage_start_date"], cfg["tat_days"], cfg["reminder1_day"], cfg["reminder2_day"],
                 cfg["owner_type"], data["action_owner_name"], data["action_owner_email"],
                 data["program_officer_email"], cfg["is_milestone"], board_id,
                 data.get("cc_emails") or None, data.get("suppress_until") or None,
                 data["application_id"]),
            )
            conn.commit()
            action = "updated"
        else:
            conn.execute(
                """INSERT INTO case_tracking
                   (application_id,programme_name,organisation_name,current_stage,stage_start_date,
                    tat_days,reminder1_day,reminder2_day,owner_type,
                    action_owner_name,action_owner_email,program_officer_email,is_milestone,board_id,
                    cc_emails,suppress_until)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (data["application_id"], data["programme_name"], data["organisation_name"],
                 data["stage_name"], data["stage_start_date"],
                 cfg["tat_days"], cfg["reminder1_day"], cfg["reminder2_day"], cfg["owner_type"],
                 data["action_owner_name"], data["action_owner_email"],
                 data["program_officer_email"], cfg["is_milestone"], board_id,
                 data.get("cc_emails") or None, data.get("suppress_until") or None),
            )
            conn.commit()
            action = "created"
    finally:
        conn.close()

    # Audit/history logging runs outside the connection (uses its own conn)
    if action == "updated":
        old_stage = existing["current_stage"]
        new_stage = data["stage_name"]
        if old_stage != new_stage:
            log_stage_transition(data["application_id"], old_stage, new_stage,
                                 data.get("_changed_by", ""), board_id)
            log_audit("stage_change", data["application_id"],
                      f"{old_stage} → {new_stage}", data.get("_changed_by", ""), board_id)
        else:
            log_audit("case_updated", data["application_id"],
                      f"Updated (stage: {new_stage})", data.get("_changed_by", ""), board_id)
    else:
        log_stage_transition(data["application_id"], None, data["stage_name"],
                             data.get("_changed_by", ""), board_id)
        log_audit("case_created", data["application_id"],
                  f"New case: {data['stage_name']}", data.get("_changed_by", ""), board_id)
    return action


# ── HTML base template ────────────────────────────────────────────────────────
_BASE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QCI Notification Engine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<style>
:root{
  --navy:#003356;--navy-dark:#002240;--navy-light:#e1eef8;
  --accent:#0094ca;--accent-dark:#007baa;--accent-light:#d0f0ff;
  --qci-green:#00984C;--qci-green-light:#d8f5e7;
  --success:#00984C;--success-light:#d8f5e7;
  --warning:#d97706;--warning-light:#fef3c7;
  --danger:#dc2626;--danger-light:#fee2e2;
  --muted:#64748b;--border:#dce5ef;--bg:#f3f6fa;
}
*{font-family:'Inter',sans-serif}
body{background:var(--bg);margin:0}

/* ── Sidebar ── */
#sidebar{
  position:fixed;top:0;left:0;width:220px;height:100vh;
  background:var(--navy-dark);z-index:100;
  display:flex;flex-direction:column;overflow-y:auto;
}
#sidebar .brand{
  padding:20px 20px 16px;border-bottom:1px solid rgba(255,255,255,.08);
}
#sidebar .brand-logo{
  font-size:18px;font-weight:700;color:#fff;letter-spacing:.3px;
  display:flex;align-items:center;gap:8px;text-decoration:none;
}
#sidebar .brand-logo span{color:#11a3d4}
#sidebar .brand-sub{font-size:10px;color:rgba(255,255,255,.4);margin-top:2px;letter-spacing:.5px;text-transform:uppercase}
#sidebar nav{padding:12px 0;flex:1}
#sidebar .nav-section{
  font-size:10px;font-weight:600;color:rgba(255,255,255,.35);
  letter-spacing:1px;text-transform:uppercase;
  padding:12px 20px 4px;
}
#sidebar .nav-link{
  display:flex;align-items:center;gap:10px;
  padding:9px 20px;color:rgba(255,255,255,.7);
  font-size:13.5px;font-weight:500;border-radius:0;
  transition:all .15s;text-decoration:none;
}
#sidebar .nav-link:hover{background:rgba(255,255,255,.07);color:#fff}
#sidebar .nav-link.active{background:var(--accent);color:#fff;border-left:3px solid #fff}
#sidebar .nav-link i{font-size:15px;width:18px;text-align:center}
#sidebar .sidebar-footer{
  padding:14px 20px;border-top:1px solid rgba(255,255,255,.08);
  font-size:11px;color:rgba(255,255,255,.3);
}
#sidebar .sidebar-search{
  padding:8px 14px 0;
}
#sidebar .sidebar-search input{
  width:100%;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);
  border-radius:6px;padding:6px 10px;color:#fff;font-size:12px;outline:none;
}
#sidebar .sidebar-search input::placeholder{color:rgba(255,255,255,.35)}
#sidebar .sidebar-search input:focus{background:rgba(255,255,255,.14);border-color:rgba(255,255,255,.3)}

/* ── Dark mode ── */
.dark-mode{
  --bg:#0f172a;--border:#1e293b;--muted:#94a3b8;
}
.dark-mode body{background:var(--bg)}
.dark-mode .card,.dark-mode .card-header,.dark-mode .topbar{background:#1e293b;color:#e2e8f0;border-color:#334155}
.dark-mode .data-table th{background:#1a2942;color:#94a3b8;border-color:#334155}
.dark-mode .data-table td{border-color:#1e293b;color:#cbd5e1}
.dark-mode .data-table tbody tr:hover td{background:#1a2942}
.dark-mode .stat-card{background:#1e293b;border-color:#334155;color:#e2e8f0}
.dark-mode .stat-card .stat-val{color:#e2e8f0}
.dark-mode .form-control,.dark-mode .form-select{background:#0f172a;border-color:#334155;color:#e2e8f0}
.dark-mode .topbar-title{color:#e2e8f0}
.dark-mode .accordion-button{background:#1e293b;color:#e2e8f0}

/* ── Overdue banner ── */
.overdue-banner{
  background:linear-gradient(90deg,#7f1d1d,#dc2626);color:#fff;
  padding:10px 28px;font-size:13px;font-weight:500;
  display:flex;align-items:center;gap:12px;
}
.overdue-banner a{color:#fca5a5;text-decoration:underline}

/* ── Main layout ── */
#main{margin-left:220px;min-height:100vh}
.topbar{
  background:#fff;border-bottom:1px solid var(--border);
  padding:0 28px;height:56px;
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:50;
}
.topbar-title{font-size:15px;font-weight:600;color:var(--navy)}
.page-body{padding:24px 28px}

/* ── Cards ── */
.card{border:1px solid var(--border);border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.card-header{background:#fff;border-bottom:1px solid var(--border);font-weight:600;font-size:14px;padding:14px 18px;border-radius:10px 10px 0 0 !important}

/* ── Stat cards ── */
.stat-card{border-radius:12px;padding:20px 22px;border:1px solid var(--border);background:#fff;transition:box-shadow .15s}
.stat-card:hover{box-shadow:0 4px 16px rgba(0,0,0,.08)}
.stat-card .stat-icon{width:46px;height:46px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}
.stat-card .stat-val{font-size:30px;font-weight:700;line-height:1;color:var(--navy);margin-top:12px}
.stat-card .stat-label{font-size:12.5px;color:var(--muted);font-weight:500;margin-top:4px}

/* ── Status pills ── */
.pill{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:600;white-space:nowrap}
.pill-ok{background:var(--success-light);color:#065f46}
.pill-warn{background:var(--warning-light);color:#92400e}
.pill-danger{background:var(--danger-light);color:#991b1b}
.pill-muted{background:#f1f5f9;color:var(--muted)}
.pill-milestone{background:#ede9fe;color:#5b21b6}

/* ── Table ── */
.data-table{border-collapse:separate;border-spacing:0;width:100%}
.data-table th{
  background:#f8fafc;font-size:11px;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.5px;
  padding:10px 14px;border-bottom:1px solid var(--border);white-space:nowrap;
}
.data-table td{padding:11px 14px;border-bottom:1px solid #f1f5f9;font-size:13px;vertical-align:middle}
.data-table tr:last-child td{border-bottom:none}
.data-table tbody tr{transition:background .1s}
.data-table tbody tr:hover td{background:#f8fafc}
.data-table td.id-cell{font-weight:600;color:var(--navy);font-size:12.5px}
.row-overdue td{background:#fff5f5}
.row-overdue td:first-child{border-left:3px solid #dc2626}
.row-overdue:hover td{background:#fee2e2 !important}

/* ── Status bar ── */
.tat-bar{height:5px;border-radius:3px;background:#e2e8f0;width:90px;overflow:hidden;margin-top:5px}
.tat-bar-fill{height:100%;border-radius:3px;transition:width .3s}

/* ── Check/cross ── */
.sent-yes{color:var(--success);font-size:15px}
.sent-no{color:#cbd5e1;font-size:15px}

/* ── Forms ── */
.form-card{border-radius:10px;overflow:hidden}
.form-section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:12px}
.form-label{font-size:13px;font-weight:500;color:#374151;margin-bottom:5px}
.form-control,.form-select{font-size:13.5px;border-color:var(--border);border-radius:7px;padding:8px 12px}
.form-control:focus,.form-select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,148,202,.12)}
.stage-info-box{background:var(--navy-light);border:1px solid #c7d9f0;border-radius:8px;padding:12px 16px;margin-top:8px;display:none}
.stage-info-box.show{display:block}

/* ── Buttons ── */
.btn{border-radius:7px;font-size:13px;font-weight:500;padding:8px 16px}
.btn-sm{padding:5px 12px;font-size:12.5px}
.btn-primary{background:var(--accent);border-color:var(--accent)}
.btn-primary:hover{background:var(--accent-dark);border-color:var(--accent-dark)}
.btn-navy{background:var(--navy);border-color:var(--navy);color:#fff}
.btn-navy:hover{background:var(--navy-dark);border-color:var(--navy-dark);color:#fff}
.btn-action{padding:3px 10px;font-size:11.5px;border-radius:5px}

/* ── Upload zone ── */
.upload-zone{
  border:2px dashed #cbd5e1;border-radius:10px;padding:36px 20px;
  text-align:center;background:#fafbfc;cursor:pointer;transition:all .2s;
}
.upload-zone:hover,.upload-zone.drag{border-color:var(--accent);background:var(--accent-light)}

/* ── Toast ── */
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999}
.qci-toast{min-width:300px;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12)}

/* ── Placeholder chips ── */
.ph-chip{
  display:inline-block;padding:2px 8px;margin:2px;border-radius:4px;
  font-size:11px;font-family:monospace;background:#f1f5f9;color:#475569;
  border:1px solid #e2e8f0;cursor:pointer;transition:background .1s;
}
.ph-chip:hover{background:var(--accent-light);color:var(--accent)}

/* ── Breadcrumb ── */
.page-crumb{font-size:12px;color:var(--muted)}
.page-crumb a{color:var(--muted);text-decoration:none}
.page-crumb a:hover{color:var(--navy)}

/* ── Accordion ── */
.accordion-button:not(.collapsed){background:var(--navy-light);color:var(--navy)}
.accordion-button:focus{box-shadow:0 0 0 3px rgba(0,148,202,.12)}

th{white-space:nowrap}
</style>
</head>
<body>

<!-- Sidebar -->
<div id="sidebar">
  <div class="brand">
    <a class="brand-logo" href="/"><i class="bi bi-bell-fill" style="color:#11a3d4"></i> QCI <span>Notify</span></a>
    <div class="brand-sub">Quality Council of India</div>
  </div>
  <div class="sidebar-search">
    <input type="text" id="sidebarSearch" placeholder="&#xF52A; Search cases…"
           onkeydown="if(event.key==='Enter'){window.location='/search?q='+encodeURIComponent(this.value)}">
  </div>
  <nav>
    <div class="nav-section">Main</div>
    <a class="nav-link {{ 'active' if active_page=='dashboard' else '' }}" href="/">
      <i class="bi bi-speedometer2"></i> Dashboard
    </a>
    <a class="nav-link {{ 'active' if active_page=='my_cases' else '' }}" href="/?my_cases=1">
      <i class="bi bi-person-check"></i> My Cases
    </a>
    <a class="nav-link {{ 'active' if active_page=='log' else '' }}" href="/log-stage">
      <i class="bi bi-plus-circle"></i> Log Stage Change
    </a>
    <a class="nav-link {{ 'active' if active_page=='bulk' else '' }}" href="/bulk-upload">
      <i class="bi bi-upload"></i> Bulk Upload
    </a>
    <a class="nav-link {{ 'active' if active_page=='bulk_advance' else '' }}" href="/bulk-advance">
      <i class="bi bi-fast-forward-fill"></i> Bulk Advance
    </a>
    <div class="nav-section" style="margin-top:8px">Reports</div>
    <a class="nav-link {{ 'active' if active_page=='reports' else '' }}" href="/reports">
      <i class="bi bi-graph-up"></i> Analytics
    </a>
    <a class="nav-link" href="/export-excel">
      <i class="bi bi-file-earmark-excel"></i> Export Excel
    </a>
    {% if user_role in ('super_admin', 'board_admin') %}
    <div class="nav-section" style="margin-top:8px">Admin</div>
    <a class="nav-link {{ 'active' if active_page=='settings' else '' }}" href="/settings">
      <i class="bi bi-sliders"></i> Programmes &amp; Stages
    </a>
    <a class="nav-link {{ 'active' if active_page=='templates' else '' }}" href="/templates">
      <i class="bi bi-envelope-paper"></i> Email Templates
    </a>
    <a class="nav-link {{ 'active' if active_page=='email_preview' else '' }}" href="/email-preview">
      <i class="bi bi-envelope-open"></i> Email Preview
    </a>
    <a class="nav-link {{ 'active' if active_page=='queue' else '' }}" href="/email-queue">
      <i class="bi bi-send-check"></i> Email Queue
    </a>
    <a class="nav-link {{ 'active' if active_page=='audit' else '' }}" href="/audit-log">
      <i class="bi bi-journal-text"></i> Audit Log
    </a>
    {% if user_role == 'super_admin' %}
    <a class="nav-link {{ 'active' if active_page=='users' else '' }}" href="/users">
      <i class="bi bi-people"></i> Manage Users
    </a>
    <a class="nav-link {{ 'active' if active_page=='system' else '' }}" href="/system-settings">
      <i class="bi bi-gear"></i> System Settings
    </a>
    <a class="nav-link" href="/backup">
      <i class="bi bi-download"></i> Backup DB
    </a>
    {% endif %}
    {% endif %}
  </nav>
  <div class="sidebar-footer">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="width:32px;height:32px;border-radius:50%;background:rgba(255,255,255,.1);
                  display:flex;align-items:center;justify-content:center;font-size:14px;color:#fff">
        <i class="bi bi-person-fill"></i>
      </div>
      <div>
        <div style="color:#fff;font-size:13px;font-weight:500">{{ user_name }}</div>
        <div style="color:rgba(255,255,255,.4);font-size:10px;text-transform:uppercase;letter-spacing:.5px">
          {% if user_role=='super_admin' %}Super Admin
          {% elif user_role=='board_admin' %}Board Admin · {{ board_name }}
          {% else %}Program Officer · {{ board_name }}{% endif %}
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between">
      <a href="/logout" style="font-size:12px;color:rgba(255,255,255,.4);text-decoration:none;
         display:flex;align-items:center;gap:6px;padding:4px 0">
        <i class="bi bi-box-arrow-left"></i> Sign out
      </a>
      <button onclick="toggleDark()" style="background:none;border:none;cursor:pointer;
              color:rgba(255,255,255,.35);font-size:15px;padding:4px" title="Toggle dark mode">
        <i class="bi bi-moon-fill" id="darkIcon"></i>
      </button>
    </div>
  </div>
</div>

<!-- Main -->
<div id="main">
  <div class="topbar">
    <div>
      <div class="topbar-title">{{ page_title }}</div>
      {% if page_crumb %}<div class="page-crumb">{{ page_crumb | safe }}</div>{% endif %}
    </div>
    <div class="d-flex align-items-center gap-2">
      {{ topbar_actions | safe }}
    </div>
  </div>

  <!-- Flash toasts -->
  <div class="toast-container">
  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}{% for cat,msg in msgs %}
  <div class="toast qci-toast show align-items-center text-white bg-{{ 'danger' if cat=='error' else ('success' if cat=='success' else 'primary') }} border-0 mb-2" role="alert">
    <div class="d-flex">
      <div class="toast-body">{{ msg }}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  </div>
  {% endfor %}{% endif %}{% endwith %}
  </div>

  <div class="page-body">
    {{ content | safe }}
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Auto-dismiss toasts after 5s
document.querySelectorAll('.toast.show').forEach(function(el){
  setTimeout(function(){ var t=bootstrap.Toast.getOrCreateInstance(el); t.hide(); }, 5000);
});
// Dark mode
function toggleDark(){
  var on = document.documentElement.classList.toggle('dark-mode');
  localStorage.setItem('qci_dark', on ? '1' : '0');
  document.getElementById('darkIcon').className = on ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
}
(function(){
  if(localStorage.getItem('qci_dark')==='1'){
    document.documentElement.classList.add('dark-mode');
    var ic = document.getElementById('darkIcon');
    if(ic) ic.className = 'bi bi-sun-fill';
  }
})();
// Quick advance modal helper
function openQuickAdvance(caseId, appId, progName){
  document.getElementById('qa_case_id').value = caseId;
  document.getElementById('qa_app_label').textContent = appId;
  fetch('/api/stages?programme=' + encodeURIComponent(progName))
    .then(r=>r.json()).then(function(stages){
      var sel = document.getElementById('qa_stage_select');
      sel.innerHTML = stages.map(s=>'<option value="'+s.name+'">'+s.name+'</option>').join('');
    });
  new bootstrap.Modal(document.getElementById('quickAdvanceModal')).show();
}
// Confirm delete
function confirmDelete(url, appId){
  if(confirm('Close case ' + appId + '? This cannot be undone.')){
    window.location = url;
  }
}
</script>
{{ scripts | safe }}
</body></html>"""


def render_page(content: str, scripts: str = "", active_page: str = "",
                page_title: str = "QCI Notification Engine",
                page_crumb: str = "", topbar_actions: str = "") -> str:
    from flask import get_flashed_messages as gfm
    user_role  = session.get("role", "")
    user_name  = session.get("full_name", "")
    board_name = session.get("board_name", "")
    return render_template_string(
        _BASE, content=content, scripts=scripts,
        active_page=active_page, page_title=page_title,
        page_crumb=page_crumb, topbar_actions=topbar_actions,
        get_flashed_messages=gfm,
        user_role=user_role, user_name=user_name, board_name=board_name,
    )


# ── Login page template (no sidebar) ─────────────────────────────────────────
_LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In — QCI Notify</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<style>
  *{font-family:'Inter',sans-serif}
  body{background:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .login-card{background:#fff;border-radius:16px;padding:40px 44px;width:100%;max-width:400px;
              box-shadow:0 4px 24px rgba(0,0,0,.08);border:1px solid #e2e8f0}
  .brand{text-align:center;margin-bottom:32px}
  .brand-icon{width:56px;height:56px;background:#1a3557;border-radius:14px;
              display:flex;align-items:center;justify-content:center;margin:0 auto 14px;font-size:24px}
  .brand-name{font-size:20px;font-weight:700;color:#1a3557}
  .brand-sub{font-size:12px;color:#94a3b8;margin-top:2px}
  .form-label{font-size:13px;font-weight:500;color:#374151}
  .form-control{border-radius:8px;border-color:#e2e8f0;padding:9px 13px;font-size:14px}
  .form-control:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.1)}
  .btn-login{background:#1a3557;color:#fff;border:none;border-radius:8px;
             padding:11px;font-size:14px;font-weight:600;width:100%}
  .btn-login:hover{background:#0f2035;color:#fff}
  .alert{border-radius:8px;font-size:13px}
  .creds-hint{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
              padding:12px 14px;margin-top:20px;font-size:12px;color:#64748b}
  .creds-hint code{background:#e2e8f0;padding:1px 5px;border-radius:3px;font-size:11px}
</style>
</head>
<body>
<div class="login-card">
  <div class="brand">
    <div class="brand-icon"><i class="bi bi-bell-fill" style="color:#fbbf24"></i></div>
    <div class="brand-name">QCI Notify</div>
    <div class="brand-sub">Quality Council of India</div>
  </div>
  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}{% for cat,msg in msgs %}
  <div class="alert alert-{{ 'danger' if cat=='error' else ('success' if cat=='success' else 'info') }}">
    {{ msg }}</div>
  {% endfor %}{% endif %}{% endwith %}
  <form method="post">
    <div class="mb-3">
      <label class="form-label">Username</label>
      <input type="text" class="form-control" name="username" autofocus required
             placeholder="Enter username" value="{{ prefill_user }}">
    </div>
    <div class="mb-{% if show_totp %}3{% else %}4{% endif %}">
      <label class="form-label">Password</label>
      <input type="password" class="form-control" name="password" required placeholder="••••••••">
    </div>
    {% if show_totp %}
    <div class="mb-4">
      <label class="form-label">Authenticator Code</label>
      <input type="text" class="form-control" name="totp_code" maxlength="6"
             placeholder="6-digit code" autocomplete="one-time-code">
    </div>
    {% endif %}
    <button type="submit" class="btn-login">Sign In</button>
  </form>
  <div class="creds-hint">
    <strong>Default credentials</strong><br>
    Admin: <code>admin</code> / <code>admin123</code><br>
    Program Officer: <code>officer</code> / <code>po123</code>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            # 2FA check
            if user["totp_secret"]:
                totp_code = request.form.get("totp_code", "").strip()
                if not totp_code:
                    flash("This account has 2FA enabled. Enter your authenticator code.", "info")
                    return render_template_string(_LOGIN_PAGE, get_flashed_messages=gfm,
                                                  show_totp=True, prefill_user=username)
                if not totp_verify(user["totp_secret"], totp_code):
                    flash("Invalid 2FA code.", "error")
                    return render_template_string(_LOGIN_PAGE, get_flashed_messages=gfm,
                                                  show_totp=True, prefill_user=username)
            session["user_id"]   = user["id"]
            session["username"]  = user["username"]
            session["role"]      = user["role"]
            session["full_name"] = user["full_name"] or user["username"]
            session["board_id"]  = user["board_id"]
            if user["board_id"]:
                conn2 = get_db()
                brow = conn2.execute("SELECT board_name FROM boards WHERE id=?", (user["board_id"],)).fetchone()
                conn2.close()
                session["board_name"] = brow["board_name"] if brow else ""
            else:
                session["board_name"] = ""
            if user["force_password_reset"]:
                flash("Please change your password before continuing.", "info")
                return redirect(url_for("force_pw_reset"))
            flash(f"Welcome back, {session['full_name']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    from flask import get_flashed_messages as gfm
    return render_template_string(_LOGIN_PAGE, get_flashed_messages=gfm,
                                  show_totp=False, prefill_user="")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/force-reset-password", methods=["GET", "POST"])
@login_required
def force_pw_reset():
    if request.method == "POST":
        new_pw = request.form.get("new_password", "").strip()
        confirm_pw = request.form.get("confirm_password", "").strip()
        if len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif new_pw != confirm_pw:
            flash("Passwords do not match.", "error")
        else:
            conn = get_db()
            conn.execute(
                "UPDATE users SET password_hash=?, force_password_reset=0 WHERE id=?",
                (generate_password_hash(new_pw), session["user_id"])
            )
            conn.commit()
            conn.close()
            flash("Password updated. Welcome!", "success")
            return redirect(url_for("dashboard"))
    content = """
<div style="max-width:420px;margin:60px auto">
  <div class="card">
    <div class="card-header" style="background:linear-gradient(135deg,var(--navy),var(--accent));color:#fff;border-radius:10px 10px 0 0">
      <i class="bi bi-shield-lock-fill"></i> Set Your Password
    </div>
    <div class="card-body p-4">
      <p style="font-size:13px;color:#64748b;margin-bottom:20px">
        You are required to set a new password before continuing.
      </p>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">New Password</label>
          <input type="password" class="form-control" name="new_password" minlength="8" required>
          <div style="font-size:11px;color:#94a3b8;margin-top:4px">Minimum 8 characters</div>
        </div>
        <div class="mb-4">
          <label class="form-label">Confirm Password</label>
          <input type="password" class="form-control" name="confirm_password" required>
        </div>
        <button class="btn btn-primary w-100">Set Password &amp; Continue</button>
      </form>
    </div>
  </div>
</div>"""
    return render_page(content, active_page="", page_title="Set New Password")


@app.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    conn = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            try:
                role = request.form["role"]
                board_id = request.form.get("board_id") or None
                if board_id:
                    board_id = int(board_id)
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, full_name, email, board_id) VALUES (?,?,?,?,?,?)",
                    (request.form["username"].strip(),
                     generate_password_hash(request.form["password"]),
                     role,
                     request.form["full_name"].strip(),
                     request.form["email"].strip(),
                     board_id),
                )
                conn.commit()
                flash(f"User '{request.form['username']}' created.", "success")
            except Exception as e:
                flash(f"Error: {e}", "error")
        elif action == "delete":
            uid = request.form.get("user_id")
            if str(uid) == str(session["user_id"]):
                flash("You cannot delete your own account.", "error")
            else:
                conn.execute("DELETE FROM users WHERE id=?", (uid,))
                conn.commit()
                flash("User deleted.", "success")
        elif action == "reset_password":
            uid = request.form.get("user_id")
            new_pw = request.form.get("new_password", "").strip()
            if new_pw:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(new_pw), uid))
                conn.commit()
                flash("Password updated.", "success")

    users = [dict(r) for r in conn.execute(
        """SELECT u.*, b.board_name FROM users u
           LEFT JOIN boards b ON b.id = u.board_id
           ORDER BY u.role, u.username"""
    ).fetchall()]
    boards = [dict(r) for r in conn.execute("SELECT * FROM boards ORDER BY board_name").fetchall()]
    conn.close()

    ROLE_LABELS = {
        "super_admin": ("Super Admin", "#dbeafe", "#1d4ed8"),
        "board_admin": ("Board Admin", "#ede9fe", "#7c3aed"),
        "program_officer": ("Program Officer", "#f1f5f9", "#475569"),
    }

    rows = ""
    for u in users:
        rl, bg, fg = ROLE_LABELS.get(u["role"], (u["role"], "#f1f5f9", "#475569"))
        role_pill = f'<span class="pill" style="background:{bg};color:{fg}">{rl}</span>'
        board_cell = u.get("board_name") or '<span style="color:#94a3b8">—</span>'
        is_self = u["id"] == session["user_id"]
        rows += f"""<tr>
          <td style="font-weight:600">{u['username']}</td>
          <td>{u['full_name'] or '—'}</td>
          <td>{u['email'] or '—'}</td>
          <td>{role_pill}</td>
          <td>{board_cell}</td>
          <td>
            <button class="btn btn-sm btn-action btn-outline-secondary"
              onclick="showResetPw({u['id']}, '{u['username']}')">Reset PW</button>
            {"" if is_self else f'''<button class="btn btn-sm btn-action btn-outline-danger ms-1"
              onclick="confirmDeleteUser({u['id']}, '{u['username']}')">Delete</button>'''}
          </td>
        </tr>"""

    board_opts = '<option value="">— None —</option>' + "".join(
        f'<option value="{b["id"]}">{b["board_name"]}</option>' for b in boards
    )

    content = f"""
<div class="row g-4">
  <div class="col-lg-8">
    <div class="card">
      <div class="card-header">All Users</div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>Username</th><th>Full Name</th><th>Email</th><th>Role</th><th>Board</th><th>Actions</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="card">
      <div class="card-header"><i class="bi bi-person-plus" style="color:#059669"></i> Add New User</div>
      <div class="card-body p-4">
        <form method="post">
          <input type="hidden" name="action" value="add">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input type="text" class="form-control" name="username" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Full Name</label>
            <input type="text" class="form-control" name="full_name">
          </div>
          <div class="mb-3">
            <label class="form-label">Email</label>
            <input type="email" class="form-control" name="email">
          </div>
          <div class="mb-3">
            <label class="form-label">Role</label>
            <select class="form-select" name="role" id="roleSelect" onchange="toggleBoardField()">
              <option value="program_officer">Program Officer</option>
              <option value="board_admin">Board Admin</option>
              <option value="super_admin">Super Admin</option>
            </select>
          </div>
          <div class="mb-3" id="boardField">
            <label class="form-label">Board <span style="color:#94a3b8;font-size:11px">(required for PO / Board Admin)</span></label>
            <select class="form-select" name="board_id">
              {board_opts}
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" class="form-control" name="password" required>
          </div>
          <button type="submit" class="btn btn-primary w-100">Create User</button>
        </form>
      </div>
    </div>
  </div>
</div>

<!-- Reset password modal -->
<div class="modal fade" id="resetPwModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered modal-sm">
    <div class="modal-content">
      <div class="modal-header border-0"><h6 class="modal-title">Reset Password — <span id="rpUser"></span></h6></div>
      <form method="post">
        <input type="hidden" name="action" value="reset_password">
        <input type="hidden" name="user_id" id="rpUserId">
        <div class="modal-body pt-0">
          <input type="password" class="form-control" name="new_password" placeholder="New password" required>
        </div>
        <div class="modal-footer border-0">
          <button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-sm btn-primary" type="submit">Update</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- Delete user modal -->
<div class="modal fade" id="delUserModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered modal-sm">
    <div class="modal-content">
      <div class="modal-body text-center p-4">
        <i class="bi bi-person-x" style="font-size:32px;color:#dc2626"></i>
        <div style="font-weight:600;margin-top:10px">Delete user <span id="delUserName"></span>?</div>
      </div>
      <form method="post">
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="user_id" id="delUserId">
        <div class="modal-footer border-0 justify-content-center gap-2">
          <button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-sm btn-danger" type="submit">Delete</button>
        </div>
      </form>
    </div>
  </div>
</div>
"""
    scripts = """<script>
function showResetPw(id, name){
  document.getElementById('rpUserId').value = id;
  document.getElementById('rpUser').textContent = name;
  new bootstrap.Modal(document.getElementById('resetPwModal')).show();
}
function confirmDeleteUser(id, name){
  document.getElementById('delUserId').value = id;
  document.getElementById('delUserName').textContent = name;
  new bootstrap.Modal(document.getElementById('delUserModal')).show();
}
function toggleBoardField(){
  var role = document.getElementById('roleSelect').value;
  document.getElementById('boardField').style.display = role === 'super_admin' ? 'none' : '';
}
toggleBoardField();
</script>"""
    return render_page(content, scripts, active_page="users", page_title="Manage Users")


@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    prog_filter  = request.args.get("programme", "")
    owner_filter = request.args.get("owner_type", "")
    my_cases     = request.args.get("my_cases", "")
    sort         = request.args.get("sort", "elapsed_desc")

    bid = user_board_id()
    if bid is not None:
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes WHERE board_id=? ORDER BY programme_name", (bid,)
        ).fetchall()]
        base_q = "SELECT * FROM case_tracking WHERE board_id=?"
        base_params = [bid]
    else:
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes ORDER BY programme_name"
        ).fetchall()]
        base_q = "SELECT * FROM case_tracking WHERE 1=1"
        base_params = []

    if prog_filter:
        base_q += " AND programme_name=?"
        base_params.append(prog_filter)
    if owner_filter:
        base_q += " AND owner_type=?"
        base_params.append(owner_filter)
    if my_cases:
        po_email = conn.execute(
            "SELECT email FROM users WHERE id=?", (session["user_id"],)
        ).fetchone()
        if po_email and po_email["email"]:
            base_q += " AND program_officer_email=?"
            base_params.append(po_email["email"])

    cases = [dict(r) for r in conn.execute(base_q, base_params).fetchall()]
    conn.close()

    today = date.today()
    for c in cases:
        c["days_elapsed"] = working_days_elapsed(c["stage_start_date"], today)

    reverse = sort.endswith("_desc")
    key = sort.replace("_desc", "").replace("_asc", "")
    key_map = {"elapsed": "days_elapsed", "app": "application_id", "org": "organisation_name"}
    sort_key = key_map.get(key, "days_elapsed")
    cases.sort(key=lambda x: (x.get(sort_key) or 0), reverse=reverse)

    # Compute stat card counts
    n_total    = len(cases)
    n_overdue  = sum(1 for c in cases if not c["is_milestone"] and c["tat_days"] > 0 and c["days_elapsed"] >= c["tat_days"])
    n_at_risk  = sum(1 for c in cases if not c["is_milestone"] and c["tat_days"] > 0
                     and c["days_elapsed"] >= c["reminder2_day"] and c["days_elapsed"] < c["tat_days"])
    n_ok       = n_total - n_overdue - n_at_risk - sum(1 for c in cases if c["is_milestone"])
    n_milestone= sum(1 for c in cases if c["is_milestone"])

    rows_html = ""
    for c in cases:
        elapsed = c["days_elapsed"]
        tat     = c["tat_days"]

        if c["is_milestone"]:
            status_pill = '<span class="pill pill-milestone"><i class="bi bi-flag-fill"></i> Milestone</span>'
            tr_cls = ""
            bar_html = ""
        elif tat > 0 and elapsed >= tat:
            status_pill = f'<span class="pill pill-danger"><i class="bi bi-exclamation-triangle-fill"></i> Overdue · {elapsed}d</span>'
            tr_cls = "row-overdue"
            pct = 100
            bar_html = f'<div class="tat-bar mt-1"><div class="tat-bar-fill" style="width:{pct}%;background:#dc2626"></div></div>'
        elif tat > 0 and elapsed >= c["reminder2_day"]:
            status_pill = f'<span class="pill pill-warn"><i class="bi bi-clock"></i> At Risk · {elapsed}d</span>'
            tr_cls = ""
            pct = min(99, int(elapsed / tat * 100)) if tat else 0
            bar_html = f'<div class="tat-bar mt-1"><div class="tat-bar-fill" style="width:{pct}%;background:#d97706"></div></div>'
        else:
            status_pill = f'<span class="pill pill-ok"><i class="bi bi-check-circle"></i> On Track · {elapsed}d</span>'
            tr_cls = ""
            pct = min(80, int(elapsed / tat * 100)) if tat else 0
            bar_html = f'<div class="tat-bar mt-1"><div class="tat-bar-fill" style="width:{pct}%;background:#00984C"></div></div>'

        def yn(v):
            return '<i class="bi bi-check-circle-fill sent-yes"></i>' if v else '<i class="bi bi-circle sent-no"></i>'

        owner_type_badge = ""
        if c.get("owner_type"):
            colors = {"Applicant": "#0094ca", "Assessor": "#7c3aed", "Program Officer": "#00984C"}
            bg = colors.get(c["owner_type"], "#64748b")
            owner_type_badge = f'<span style="font-size:10px;padding:1px 7px;border-radius:4px;background:{bg}22;color:{bg};font-weight:600">{c["owner_type"]}</span> '

        rows_html += f"""<tr class="{tr_cls}">
          <td class="id-cell">{c['application_id']}</td>
          <td><div style="font-weight:500;color:#1e293b">{c['organisation_name']}</div>
              <div style="font-size:11px;color:#94a3b8">{c['programme_name']}</div></td>
          <td><div style="font-size:13px">{c['current_stage']}</div>
              <div style="font-size:11px;color:#94a3b8">{owner_type_badge}Start: {c['stage_start_date']}</div></td>
          <td><div>{status_pill}</div>{bar_html}</td>
          <td class="text-center">{yn(c['r1_sent'])}</td>
          <td class="text-center">{yn(c['r2_sent'])}</td>
          <td class="text-center">{yn(c['overdue_sent'])}</td>
          <td class="text-center" style="font-weight:600;color:{'#dc2626' if c['overdue_count'] else '#94a3b8'}">{c['overdue_count'] or '—'}</td>
          <td><div style="font-size:12.5px">{c['action_owner_name'] or '—'}</div>
              <div style="font-size:11px;color:#94a3b8">{c['action_owner_email'] or ''}</div></td>
          <td style="white-space:nowrap">
            <a href="/case-history/{c['application_id']}" class="btn btn-sm btn-action btn-outline-secondary me-1"
               title="History"><i class="bi bi-clock-history"></i></a>
            <button class="btn btn-sm btn-action btn-outline-success me-1" title="Quick Advance"
               onclick="openQuickAdvance({c['id']}, '{c['application_id']}', '{c['programme_name']}')">
               <i class="bi bi-arrow-right-circle"></i></button>
            <a href="/edit-case/{c['id']}" class="btn btn-sm btn-action btn-outline-primary me-1">Edit</a>
            <button class="btn btn-sm btn-action btn-outline-danger"
              onclick="confirmDelete('/delete-case/{c['id']}', '{c['application_id']}')">Close</button>
          </td>
        </tr>"""

    opt_programmes = "".join(
        f'<option value="{p}" {"selected" if p==prog_filter else ""}>{p}</option>'
        for p in programmes
    )

    stat_cards = f"""
<div class="row g-3 mb-4">
  <div class="col-6 col-md-3">
    <div class="stat-card">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <div class="stat-val">{n_total}</div>
          <div class="stat-label">Total Active Cases</div>
        </div>
        <div class="stat-icon" style="background:#e1eef8;color:#003356"><i class="bi bi-folder2-open"></i></div>
      </div>
    </div>
  </div>
  <div class="col-6 col-md-3">
    <div class="stat-card">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <div class="stat-val" style="color:#00984C">{n_ok}</div>
          <div class="stat-label">On Track</div>
        </div>
        <div class="stat-icon" style="background:#d8f5e7;color:#00984C"><i class="bi bi-check-circle-fill"></i></div>
      </div>
    </div>
  </div>
  <div class="col-6 col-md-3">
    <div class="stat-card">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <div class="stat-val" style="color:#d97706">{n_at_risk}</div>
          <div class="stat-label">At Risk</div>
        </div>
        <div class="stat-icon" style="background:#fef3c7;color:#d97706"><i class="bi bi-clock-fill"></i></div>
      </div>
    </div>
  </div>
  <div class="col-6 col-md-3">
    <div class="stat-card">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <div class="stat-val" style="color:#dc2626">{n_overdue}</div>
          <div class="stat-label">Overdue</div>
        </div>
        <div class="stat-icon" style="background:#fee2e2;color:#dc2626"><i class="bi bi-exclamation-triangle-fill"></i></div>
      </div>
    </div>
  </div>
</div>"""

    empty_html = """
<div style="text-align:center;padding:60px 20px;color:#94a3b8">
  <i class="bi bi-inbox" style="font-size:48px;display:block;margin-bottom:12px"></i>
  <div style="font-size:15px;font-weight:500">No cases found</div>
  <div style="font-size:13px;margin-top:4px">Log a stage change or upload a CSV to get started.</div>
  <a href="/log-stage" class="btn btn-primary mt-3 btn-sm">Log a Stage</a>
</div>"""

    # ── Owner-type pendency breakdown ──
    owner_counts = {}
    owner_overdue = {}
    for c in cases:
        ot = c.get("owner_type") or "Unassigned"
        owner_counts[ot] = owner_counts.get(ot, 0) + 1
        if not c["is_milestone"] and c["tat_days"] > 0 and c["days_elapsed"] >= c["tat_days"]:
            owner_overdue[ot] = owner_overdue.get(ot, 0) + 1

    OWNER_META = {
        "Applicant":       ("#0094ca", "bi-person-fill"),
        "Assessor":        ("#7c3aed", "bi-clipboard-check"),
        "Program Officer": ("#00984C", "bi-headset"),
        "Unassigned":      ("#94a3b8", "bi-question-circle"),
    }

    owner_cards_html = ""
    for ot in ["Applicant", "Assessor", "Program Officer", "Unassigned"]:
        cnt = owner_counts.get(ot, 0)
        if cnt == 0 and ot == "Unassigned":
            continue
        od = owner_overdue.get(ot, 0)
        color, icon = OWNER_META.get(ot, ("#94a3b8", "bi-circle"))
        od_badge = f'<span style="font-size:11px;padding:2px 8px;border-radius:6px;background:#fee2e2;color:#dc2626;font-weight:600">{od} overdue</span>' if od else '<span style="font-size:11px;color:#94a3b8">0 overdue</span>'
        pct = int(cnt / n_total * 100) if n_total else 0
        owner_cards_html += f"""<div class="col-6 col-lg-3">
  <div class="stat-card" style="border-left:4px solid {color}">
    <div class="d-flex justify-content-between align-items-start">
      <div>
        <div class="stat-val" style="font-size:24px;color:{color}">{cnt}</div>
        <div class="stat-label">{ot}</div>
        <div style="margin-top:6px">{od_badge}</div>
      </div>
      <div class="stat-icon" style="background:{color}15;color:{color}"><i class="bi {icon}"></i></div>
    </div>
    <div class="tat-bar mt-2" style="width:100%"><div class="tat-bar-fill" style="width:{pct}%;background:{color}"></div></div>
    <div style="font-size:10px;color:#94a3b8;margin-top:2px">{pct}% of total</div>
  </div>
</div>"""

    # ── Programme-wise summary for analytics ──
    prog_summary = {}
    for c in cases:
        pn = c["programme_name"]
        if pn not in prog_summary:
            prog_summary[pn] = {"total": 0, "overdue": 0, "on_track": 0, "at_risk": 0}
        prog_summary[pn]["total"] += 1
        if c["is_milestone"]:
            continue
        if c["tat_days"] > 0 and c["days_elapsed"] >= c["tat_days"]:
            prog_summary[pn]["overdue"] += 1
        elif c["tat_days"] > 0 and c["days_elapsed"] >= c["reminder2_day"]:
            prog_summary[pn]["at_risk"] += 1
        else:
            prog_summary[pn]["on_track"] += 1

    prog_rows_html = ""
    for pn, ps in sorted(prog_summary.items()):
        health = ps["on_track"] / ps["total"] * 100 if ps["total"] else 0
        prog_rows_html += f"""<tr>
  <td style="font-weight:600;font-size:12.5px">{pn}</td>
  <td class="text-center">{ps['total']}</td>
  <td class="text-center" style="color:#00984C;font-weight:600">{ps['on_track']}</td>
  <td class="text-center" style="color:#d97706;font-weight:600">{ps['at_risk']}</td>
  <td class="text-center" style="color:#dc2626;font-weight:600">{ps['overdue']}</td>
  <td>
    <div class="tat-bar" style="width:100%;height:7px">
      <div class="tat-bar-fill" style="width:{health:.0f}%;background:#00984C"></div>
    </div>
    <div style="font-size:10px;color:#94a3b8">{health:.0f}% healthy</div>
  </td>
</tr>"""

    # ── Ageing analysis ──
    age_buckets = {"0-7 days": 0, "8-15 days": 0, "16-30 days": 0, "31-60 days": 0, "60+ days": 0}
    for c in cases:
        e = c["days_elapsed"]
        if e <= 7:
            age_buckets["0-7 days"] += 1
        elif e <= 15:
            age_buckets["8-15 days"] += 1
        elif e <= 30:
            age_buckets["16-30 days"] += 1
        elif e <= 60:
            age_buckets["31-60 days"] += 1
        else:
            age_buckets["60+ days"] += 1

    AGE_COLORS = {"0-7 days": "#00984C", "8-15 days": "#0094ca", "16-30 days": "#d97706", "31-60 days": "#f93822", "60+ days": "#dc2626"}
    age_bars_html = ""
    for lbl, cnt in age_buckets.items():
        pct = int(cnt / n_total * 100) if n_total else 0
        clr = AGE_COLORS[lbl]
        age_bars_html += f"""<div class="d-flex align-items-center gap-2 mb-2">
  <div style="width:70px;font-size:12px;font-weight:500;color:#475569">{lbl}</div>
  <div style="flex:1;height:20px;background:#f1f5f9;border-radius:4px;overflow:hidden">
    <div style="width:{pct}%;height:100%;background:{clr};border-radius:4px;min-width:{('24px' if cnt else '0')}"></div>
  </div>
  <div style="width:36px;text-align:right;font-size:12px;font-weight:600;color:#475569">{cnt}</div>
</div>"""

    # ── SLA compliance metric ──
    sla_eligible = [c for c in cases if not c["is_milestone"] and c["tat_days"] > 0]
    sla_within = sum(1 for c in sla_eligible if c["days_elapsed"] < c["tat_days"])
    sla_pct = int(sla_within / len(sla_eligible) * 100) if sla_eligible else 100
    sla_color = "#00984C" if sla_pct >= 80 else ("#d97706" if sla_pct >= 60 else "#dc2626")

    # ── Notification coverage ──
    notif_eligible = [c for c in cases if not c["is_milestone"] and c["tat_days"] > 0]
    r1_coverage = sum(1 for c in notif_eligible if c["r1_sent"]) if notif_eligible else 0
    r1_pct = int(r1_coverage / len(notif_eligible) * 100) if notif_eligible else 0

    analytics_section = f"""
<div class="row g-3 mb-4">
  <div class="col-12">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:8px">
      <i class="bi bi-people-fill"></i> Pendency by Owner Type
    </div>
  </div>
  {owner_cards_html}
</div>

<div class="row g-3 mb-4">
  <div class="col-lg-7">
    <div class="card">
      <div class="card-header"><i class="bi bi-bar-chart-fill" style="color:var(--accent)"></i> Programme Health</div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr>
            <th>Programme</th>
            <th style="text-align:center">Total</th>
            <th style="text-align:center">On Track</th>
            <th style="text-align:center">At Risk</th>
            <th style="text-align:center">Overdue</th>
            <th>Health</th>
          </tr></thead>
          <tbody>{prog_rows_html if prog_rows_html else '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px">No data</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card mb-3">
      <div class="card-header"><i class="bi bi-hourglass-split" style="color:#d97706"></i> Case Ageing</div>
      <div class="card-body">
        {age_bars_html}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><i class="bi bi-shield-check" style="color:{sla_color}"></i> SLA Compliance</div>
      <div class="card-body text-center" style="padding:20px">
        <div style="font-size:48px;font-weight:700;color:{sla_color};line-height:1">{sla_pct}%</div>
        <div style="font-size:12px;color:#64748b;margin-top:4px">of cases within TAT</div>
        <div class="tat-bar mt-3 mx-auto" style="width:80%;height:8px">
          <div class="tat-bar-fill" style="width:{sla_pct}%;background:{sla_color}"></div>
        </div>
        <div class="d-flex justify-content-between mt-2" style="font-size:11px;color:#94a3b8;width:80%;margin:0 auto">
          <span>{sla_within} within TAT</span>
          <span>{len(sla_eligible) - sla_within} breached</span>
        </div>
        <hr style="margin:16px 0;border-color:#f1f5f9">
        <div class="d-flex justify-content-center gap-4">
          <div>
            <div style="font-size:20px;font-weight:700;color:var(--accent)">{r1_pct}%</div>
            <div style="font-size:11px;color:#94a3b8">R1 Coverage</div>
          </div>
          <div>
            <div style="font-size:20px;font-weight:700;color:var(--navy)">{len(sla_eligible)}</div>
            <div style="font-size:11px;color:#94a3b8">TAT-tracked</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
"""

    # Overdue banner
    overdue_banner_html = ""
    if n_overdue > 0 and not prog_filter and not owner_filter and not my_cases:
        overdue_banner_html = f"""
<div class="overdue-banner">
  <i class="bi bi-exclamation-triangle-fill" style="font-size:18px"></i>
  <span><strong>{n_overdue} case{"s" if n_overdue!=1 else ""} overdue</strong> — immediate attention required.</span>
  <a href="/?owner_type=Applicant">View Applicant</a>
  <a href="/?owner_type=Assessor">View Assessor</a>
  <a href="/?owner_type=Program+Officer">View PO</a>
</div>"""

    content = f"""
{overdue_banner_html}
{stat_cards}
{analytics_section}

<div class="card">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span>Active Cases <span style="font-size:12px;font-weight:400;color:#94a3b8;margin-left:6px">{len(cases)} total</span></span>
    <form method="get" class="d-flex gap-2 align-items-center flex-wrap">
      <select name="programme" class="form-select form-select-sm" style="width:auto">
        <option value="">All Programmes</option>
        {opt_programmes}
      </select>
      <select name="owner_type" class="form-select form-select-sm" style="width:auto">
        <option value="">All Owners</option>
        <option value="Applicant" {"selected" if owner_filter=="Applicant" else ""}>Applicant</option>
        <option value="Assessor" {"selected" if owner_filter=="Assessor" else ""}>Assessor</option>
        <option value="Program Officer" {"selected" if owner_filter=="Program Officer" else ""}>Program Officer</option>
      </select>
      <select name="sort" class="form-select form-select-sm" style="width:auto">
        <option value="elapsed_desc" {"selected" if sort=="elapsed_desc" else ""}>Days Elapsed ↓</option>
        <option value="elapsed_asc"  {"selected" if sort=="elapsed_asc" else ""}>Days Elapsed ↑</option>
        <option value="app_asc"      {"selected" if sort=="app_asc" else ""}>Application ID</option>
        <option value="org_asc"      {"selected" if sort=="org_asc" else ""}>Organisation</option>
      </select>
      <button class="btn btn-sm btn-primary" type="submit">Filter</button>
      {"" if not (prog_filter or owner_filter) else '<a class="btn btn-sm btn-outline-secondary" href="/">Clear</a>'}
    </form>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table">
      <thead>
        <tr>
          <th>Application ID</th>
          <th>Organisation / Programme</th>
          <th>Stage</th>
          <th>Status</th>
          <th style="text-align:center">R1</th>
          <th style="text-align:center">R2</th>
          <th style="text-align:center">Overdue</th>
          <th style="text-align:center">Follow-ups</th>
          <th>Action Owner</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {rows_html if rows_html else f'<tr><td colspan="10">{empty_html}</td></tr>'}
      </tbody>
    </table>
  </div>
</div>

<!-- Delete confirmation modal -->
<div class="modal fade" id="deleteModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered modal-sm">
    <div class="modal-content">
      <div class="modal-body text-center p-4">
        <i class="bi bi-trash3" style="font-size:32px;color:#dc2626"></i>
        <div style="font-weight:600;margin-top:10px">Close Case?</div>
        <div style="font-size:13px;color:#64748b;margin-top:4px" id="deleteModalMsg"></div>
      </div>
      <div class="modal-footer border-0 pt-0 justify-content-center gap-2">
        <button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
        <a id="deleteConfirmBtn" href="#" class="btn btn-sm btn-danger">Close Case</a>
      </div>
    </div>
  </div>
</div>

<!-- Quick Advance modal -->
<div class="modal fade" id="quickAdvanceModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header border-0 pb-0">
        <h6 class="modal-title"><i class="bi bi-arrow-right-circle-fill" style="color:#059669"></i>
          Quick Stage Advance — <span id="qa_app_label" style="color:#64748b;font-weight:400"></span></h6>
        <button class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <form method="post" action="/quick-advance">
        <input type="hidden" name="case_id" id="qa_case_id">
        <div class="modal-body">
          <div class="mb-3">
            <label class="form-label">Move to Stage</label>
            <select class="form-select" id="qa_stage_select" name="target_stage" required>
              <option value="">Loading…</option>
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Start Date <span style="color:#94a3b8;font-size:11px">(new stage)</span></label>
            <input type="date" class="form-control" name="new_start_date"
                   value="{date.today().strftime('%Y-%m-%d')}">
          </div>
          <div class="mb-1">
            <label class="form-label">Suppress Notifications Until <span style="color:#94a3b8;font-size:11px">(optional)</span></label>
            <input type="date" class="form-control" name="suppress_until">
          </div>
        </div>
        <div class="modal-footer border-0">
          <button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
          <button class="btn btn-sm btn-success" type="submit">
            <i class="bi bi-arrow-right-circle"></i> Advance Stage
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- Run check result toast -->
<div id="runToast" class="toast qci-toast" role="alert" style="position:fixed;bottom:24px;right:24px;z-index:9999;min-width:320px">
  <div class="toast-header">
    <i class="bi bi-play-circle-fill text-success me-2"></i>
    <strong class="me-auto">Check Complete</strong>
    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
  </div>
  <div class="toast-body" id="runToastBody"></div>
</div>
"""
    topbar_actions = """
<a href="/export-dashboard" class="btn btn-sm btn-outline-secondary">
  <i class="bi bi-download"></i> Export CSV
</a>
<a href="/log-stage" class="btn btn-sm btn-navy">
  <i class="bi bi-plus-circle"></i> Log Stage
</a>
<button class="btn btn-sm btn-warning" id="runBtn">
  <i class="bi bi-play-fill"></i> Run Check
</button>"""

    scripts = """<script>
function confirmDelete(url, appId){
  document.getElementById('deleteModalMsg').textContent = 'This will close case ' + appId + '.';
  document.getElementById('deleteConfirmBtn').href = url;
  new bootstrap.Modal(document.getElementById('deleteModal')).show();
}
document.getElementById('runBtn').addEventListener('click', function(){
  var btn = this;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  btn.disabled = true;
  fetch('/run-check').then(r=>r.json()).then(d=>{
    var msg = 'R1: <strong>'+d.r1+'</strong> &nbsp; R2: <strong>'+d.r2+'</strong> &nbsp; Overdue: <strong>'+d.overdue+'</strong> &nbsp; Follow-ups: <strong>'+d.followup+'</strong>';
    if(d.errors && d.errors.length) msg += '<br><small class="text-danger">'+d.errors.length+' error(s)</small>';
    document.getElementById('runToastBody').innerHTML = msg;
    new bootstrap.Toast(document.getElementById('runToast')).show();
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Run Check';
    btn.disabled = false;
    setTimeout(function(){ location.reload(); }, 2500);
  }).catch(function(err){
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Run Check';
    btn.disabled = false;
  });
});
</script>"""
    return render_page(content, scripts, active_page="dashboard",
                       page_title="Dashboard", topbar_actions=topbar_actions)


@app.route("/log-stage", methods=["GET", "POST"])
@login_required
def log_stage():
    conn = get_db()
    bid = user_board_id()
    if bid is not None:
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes WHERE board_id=? ORDER BY programme_name", (bid,)
        ).fetchall()]
    else:
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes ORDER BY programme_name"
        ).fetchall()]
    conn.close()

    if request.method == "POST":
        data = {
            "application_id":     request.form["application_id"].strip(),
            "organisation_name":  request.form["organisation_name"].strip(),
            "programme_name":     request.form["programme_name"].strip(),
            "stage_name":         request.form["stage_name"].strip(),
            "stage_start_date":   request.form["stage_start_date"].strip(),
            "action_owner_name":  request.form["action_owner_name"].strip(),
            "action_owner_email": request.form["action_owner_email"].strip(),
            "program_officer_email": request.form["program_officer_email"].strip(),
        }
        try:
            data["_changed_by"] = session.get("full_name") or session.get("username", "")
            action = upsert_case(data)
            flash(f"Case {data['application_id']} {action} successfully.", "success")
            return redirect(url_for("dashboard"))
        except ValueError as e:
            flash(str(e), "error")

    opts = "".join(f'<option value="{p}">{p}</option>' for p in programmes)
    content = f"""
<div class="row g-4 justify-content-center" style="max-width:860px;margin:0 auto">

  <!-- Left column: Case details -->
  <div class="col-lg-7">
    <div class="card form-card">
      <div class="card-header">
        <i class="bi bi-file-earmark-text" style="color:#2563eb"></i> Case Details
      </div>
      <div class="card-body p-4">
        <form method="post" id="logForm">

          <div class="form-section-title">Programme &amp; Stage</div>
          <div class="mb-3">
            <label class="form-label">Programme</label>
            <select class="form-select" name="programme_name" id="progSelect" required>
              <option value="">Select a programme…</option>
              {opts}
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Stage</label>
            <select class="form-select" name="stage_name" id="stageSelect" required>
              <option value="">Select programme first…</option>
            </select>
            <div class="stage-info-box" id="stageInfoBox">
              <div class="d-flex gap-3 flex-wrap">
                <div><span style="font-size:11px;color:#64748b">TAT</span><br><strong id="si_tat">—</strong> days</div>
                <div><span style="font-size:11px;color:#64748b">Reminder 1</span><br>Day <strong id="si_r1">—</strong></div>
                <div><span style="font-size:11px;color:#64748b">Reminder 2</span><br>Day <strong id="si_r2">—</strong></div>
                <div><span style="font-size:11px;color:#64748b">Owner</span><br><strong id="si_owner">—</strong></div>
                <div id="si_ms_div" style="display:none"><span style="font-size:11px;color:#64748b">Type</span><br>
                  <span class="pill pill-milestone" style="font-size:11px"><i class="bi bi-flag-fill"></i> Milestone</span></div>
              </div>
            </div>
          </div>

          <hr style="border-color:#f1f5f9;margin:20px 0">
          <div class="form-section-title">Application Info</div>
          <div class="row g-3 mb-3">
            <div class="col-md-6">
              <label class="form-label">Application ID</label>
              <input type="text" class="form-control" name="application_id"
                     placeholder="e.g. NABH-2025-001" required>
            </div>
            <div class="col-md-6">
              <label class="form-label">Date of Stage Change</label>
              <input type="date" class="form-control" name="stage_start_date"
                     value="{date.today().isoformat()}" required>
            </div>
          </div>
          <div class="mb-3">
            <label class="form-label">Organisation Name</label>
            <input type="text" class="form-control" name="organisation_name"
                   placeholder="Hospital / Organisation name" required>
          </div>

          <hr style="border-color:#f1f5f9;margin:20px 0">
          <div class="form-section-title">People</div>
          <div class="mb-3">
            <label class="form-label">Your Email (Program Officer)</label>
            <input type="email" class="form-control" name="program_officer_email"
                   placeholder="po@qci.org.in" required>
          </div>
          <div class="row g-3">
            <div class="col-md-6">
              <label class="form-label">Action Owner Name</label>
              <input type="text" class="form-control" name="action_owner_name" required>
            </div>
            <div class="col-md-6">
              <label class="form-label">Action Owner Email</label>
              <input type="email" class="form-control" name="action_owner_email" required>
            </div>
          </div>

          <button type="submit" class="btn btn-primary w-100 mt-4" style="padding:10px">
            <i class="bi bi-check2-circle"></i> Submit Stage Change
          </button>
        </form>
      </div>
    </div>
  </div>

  <!-- Right column: help -->
  <div class="col-lg-5 d-none d-lg-block">
    <div class="card" style="background:#f8fafc;border-style:dashed">
      <div class="card-body p-4">
        <div style="font-weight:600;font-size:14px;color:#1a3557;margin-bottom:12px">
          <i class="bi bi-info-circle"></i> How this works
        </div>
        <ul style="font-size:13px;color:#475569;line-height:1.9;padding-left:18px">
          <li>If the Application ID already exists, the row is <strong>updated</strong> and all sent-flags are reset.</li>
          <li>If it's new, a <strong>new case</strong> is created.</li>
          <li>TAT, reminders, and owner type are pulled from the selected programme configuration.</li>
          <li>Milestone stages receive <strong>no emails</strong>.</li>
          <li>The daily scheduler runs at the configured time (IST); change it in <strong>Settings → Scheduler Settings</strong>. Use Run Check on the dashboard to trigger immediately.</li>
        </ul>
        <div style="margin-top:16px;padding:12px 14px;background:#fff;border-radius:8px;border:1px solid #e2e8f0">
          <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Need bulk upload?</div>
          <a href="/bulk-upload" class="btn btn-sm btn-outline-primary w-100">
            <i class="bi bi-upload"></i> Go to Bulk Upload
          </a>
        </div>
      </div>
    </div>
  </div>

</div>
"""
    scripts = """<script>
var _stageData = {};
document.getElementById('progSelect').addEventListener('change', function(){
  var prog = this.value;
  var sel = document.getElementById('stageSelect');
  var box = document.getElementById('stageInfoBox');
  sel.innerHTML = '<option value="">Loading…</option>';
  box.classList.remove('show');
  _stageData = {};
  if(!prog){ sel.innerHTML='<option value="">Select programme first…</option>'; return; }
  fetch('/api/stages?programme='+encodeURIComponent(prog))
    .then(r=>r.json())
    .then(data=>{
      _stageData = {};
      data.forEach(function(s){ _stageData[s.stage_name] = s; });
      sel.innerHTML = '<option value="">Select a stage…</option>' +
        data.map(s=>'<option value="'+s.stage_name+'">'+(s.is_milestone ? '⬥ ' : '')+s.stage_name+'</option>').join('');
    });
});
document.getElementById('stageSelect').addEventListener('change', function(){
  var s = _stageData[this.value];
  var box = document.getElementById('stageInfoBox');
  if(!s){ box.classList.remove('show'); return; }
  document.getElementById('si_tat').textContent   = s.tat_days || '0';
  document.getElementById('si_r1').textContent    = s.reminder1_day || '—';
  document.getElementById('si_r2').textContent    = s.reminder2_day || '—';
  document.getElementById('si_owner').textContent = s.owner_type || '—';
  document.getElementById('si_ms_div').style.display = s.is_milestone ? '' : 'none';
  box.classList.add('show');
});
</script>"""
    return render_page(content, scripts, active_page="log",
                       page_title="Log Stage Change",
                       page_crumb='<a href="/">Dashboard</a> / Log Stage Change')


@app.route("/api/stages")
@login_required
def api_stages():
    programme = request.args.get("programme", "")
    conn = get_db()
    bid = user_board_id()
    # Verify programme belongs to user's board (unless super_admin)
    if bid is not None:
        allowed = conn.execute(
            "SELECT id FROM programmes WHERE programme_name=? AND board_id=?", (programme, bid)
        ).fetchone()
        if not allowed:
            conn.close()
            return jsonify([])
    rows = conn.execute(
        "SELECT stage_name, stage_order, is_milestone, tat_days, reminder1_day, reminder2_day, owner_type "
        "FROM programme_config WHERE programme_name=? ORDER BY stage_order",
        (programme,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/bulk-upload", methods=["GET", "POST"])
@login_required
def bulk_upload():
    REQUIRED_COLS = {"Application_ID", "Organisation_Name", "Programme_Name",
                     "Stage_Name", "Date_of_Stage_Change",
                     "Action_Owner_Name", "Action_Owner_Email", "Program_Officer_Email"}

    if request.method == "POST":
        f = request.files.get("upload_file")
        if not f or not f.filename:
            flash("No file uploaded.", "error")
            return redirect(url_for("bulk_upload"))

        fname = f.filename.lower()
        created = updated = failed = 0
        errors = []
        row_dicts = []

        try:
            if fname.endswith(".xlsx") or fname.endswith(".xls"):
                if not HAS_XLSX:
                    flash("openpyxl is not installed. Install it with: pip3 install openpyxl", "error")
                    return redirect(url_for("bulk_upload"))
                wb = openpyxl.load_workbook(io.BytesIO(f.stream.read()))
                ws = wb.active
                all_rows = list(ws.iter_rows(values_only=True))
                if not all_rows:
                    flash("The uploaded file is empty.", "error")
                    return redirect(url_for("bulk_upload"))
                headers = [str(h).strip() if h else "" for h in all_rows[0]]
                row_dicts = [
                    {headers[i]: (str(v).strip() if v is not None else "")
                     for i, v in enumerate(row) if i < len(headers)}
                    for row in all_rows[1:]
                ]
            else:
                raw = f.stream.read()
                stream = io.StringIO(raw.decode("utf-8-sig"))
                reader = csv.DictReader(stream)
                headers = list(reader.fieldnames or [])
                row_dicts = list(reader)

            if not REQUIRED_COLS.issubset(set(headers)):
                missing = REQUIRED_COLS - set(headers)
                flash(f"File missing columns: {', '.join(sorted(missing))}", "error")
                return redirect(url_for("bulk_upload"))

        except Exception as e:
            flash(f"Could not read file: {e}", "error")
            return redirect(url_for("bulk_upload"))

        for i, row in enumerate(row_dicts, start=2):
            try:
                data = {
                    "application_id":     row.get("Application_ID", "").strip(),
                    "organisation_name":  row.get("Organisation_Name", "").strip(),
                    "programme_name":     row.get("Programme_Name", "").strip(),
                    "stage_name":         row.get("Stage_Name", "").strip(),
                    "stage_start_date":   row.get("Date_of_Stage_Change", "").strip(),
                    "action_owner_name":  row.get("Action_Owner_Name", "").strip(),
                    "action_owner_email": row.get("Action_Owner_Email", "").strip(),
                    "program_officer_email": row.get("Program_Officer_Email", "").strip(),
                    "cc_emails":          row.get("CC_Emails", "").strip(),
                    "_changed_by":        session.get("full_name") or session.get("username", ""),
                }
                if not data["application_id"]:
                    raise ValueError("Application_ID is empty")
                action = upsert_case(data)
                if action == "created":
                    created += 1
                else:
                    updated += 1
            except Exception as e:
                failed += 1
                errors.append({"row": i, "app_id": row.get("Application_ID", ""),
                                "reason": str(e)})

        log_audit("bulk_upload", None,
                  f"Uploaded: {created} created, {updated} updated, {failed} failed",
                  session.get("full_name") or session.get("username", ""), user_board_id())

        if errors and request.form.get("download_errors"):
            # Download error report as CSV
            out = io.StringIO()
            w = csv.DictWriter(out, fieldnames=["Row", "Application_ID", "Reason"])
            w.writeheader()
            for e in errors:
                w.writerow({"Row": e["row"], "Application_ID": e["app_id"], "Reason": e["reason"]})
            out.seek(0)
            return Response(out.getvalue(), mimetype="text/csv",
                            headers={"Content-Disposition": "attachment;filename=upload_errors.csv"})

        msg = f"Upload complete — {created} created, {updated} updated, {failed} failed"
        if errors:
            msg += f". <strong>{failed} row(s) failed</strong> — resubmit with 'Download Error Report' checked."
        flash(msg, "success" if not failed else "warning")
        return redirect(url_for("bulk_upload"))

    content = """
<div class="row g-4 justify-content-center" style="max-width:860px;margin:0 auto">
  <div class="col-lg-7">
    <div class="card form-card">
      <div class="card-header"><i class="bi bi-upload" style="color:#059669"></i> Upload CSV File</div>
      <div class="card-body p-4">

        <!-- Step 1 -->
        <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:24px">
          <div style="min-width:32px;height:32px;border-radius:50%;background:#e8eef7;color:#1a3557;font-weight:700;font-size:14px;display:flex;align-items:center;justify-content:center">1</div>
          <div style="flex:1">
            <div style="font-weight:600;font-size:14px;margin-bottom:4px">Download the template</div>
            <div style="font-size:13px;color:#64748b;margin-bottom:10px">Fill in your data, then upload below.</div>
            <div class="d-flex gap-2">
              <a href="/csv-template" class="btn btn-sm btn-outline-primary">
                <i class="bi bi-filetype-csv"></i> CSV Template
              </a>
              <a href="/xlsx-template" class="btn btn-sm btn-outline-success">
                <i class="bi bi-file-earmark-excel"></i> Excel Template
              </a>
            </div>
          </div>
        </div>

        <hr style="border-color:#f1f5f9">

        <!-- Step 2 -->
        <div style="display:flex;align-items:flex-start;gap:14px;margin-top:24px">
          <div style="min-width:32px;height:32px;border-radius:50%;background:#e8eef7;color:#1a3557;font-weight:700;font-size:14px;display:flex;align-items:center;justify-content:center">2</div>
          <div style="flex:1">
            <div style="font-weight:600;font-size:14px;margin-bottom:4px">Upload your filled CSV</div>
            <form method="post" enctype="multipart/form-data" id="uploadForm">
              <label class="upload-zone" for="csvInput" id="uploadZone">
                <i class="bi bi-cloud-upload" style="font-size:32px;color:#94a3b8;display:block;margin-bottom:8px"></i>
                <div style="font-weight:500;color:#475569">Drop file here or click to browse</div>
                <div style="font-size:12px;color:#94a3b8;margin-top:4px">Accepts <strong>.csv</strong> and <strong>.xlsx</strong></div>
                <div style="font-size:12px;color:#64748b;margin-top:6px;font-weight:500" id="fileLabel">No file selected</div>
                <input type="file" id="csvInput" name="upload_file" accept=".csv,.xlsx,.xls" required style="display:none">
              </label>
              <div class="form-check mt-3 mb-1" style="font-size:12px">
                <input class="form-check-input" type="checkbox" name="download_errors" id="dlErrCheck" value="1">
                <label class="form-check-label" for="dlErrCheck">Download error report if any rows fail</label>
              </div>
              <button type="submit" class="btn btn-primary w-100 mt-2" style="padding:10px">
                <i class="bi bi-upload"></i> Upload &amp; Process
              </button>
            </form>
          </div>
        </div>

      </div>
    </div>
  </div>

  <div class="col-lg-5">
    <div class="card">
      <div class="card-header"><i class="bi bi-table" style="color:#7c3aed"></i> Required Columns</div>
      <div class="card-body p-0">
        <table class="data-table">
          <thead><tr><th>Column</th><th>Example</th></tr></thead>
          <tbody>
            <tr><td><code>Application_ID</code></td><td style="color:#64748b;font-size:12px">NABH-2025-001</td></tr>
            <tr><td><code>Organisation_Name</code></td><td style="color:#64748b;font-size:12px">City Hospital</td></tr>
            <tr><td><code>Programme_Name</code></td><td style="color:#64748b;font-size:12px">NABH Full Accreditation…</td></tr>
            <tr><td><code>Stage_Name</code></td><td style="color:#64748b;font-size:12px">Application In Progress</td></tr>
            <tr><td><code>Date_of_Stage_Change</code></td><td style="color:#64748b;font-size:12px">2026-03-20</td></tr>
            <tr><td><code>Action_Owner_Name</code></td><td style="color:#64748b;font-size:12px">Mr. Applicant</td></tr>
            <tr><td><code>Action_Owner_Email</code></td><td style="color:#64748b;font-size:12px">applicant@hospital.in</td></tr>
            <tr><td><code>Program_Officer_Email</code></td><td style="color:#64748b;font-size:12px">po@qci.org.in</td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="card mt-3" style="background:#fffbeb;border-color:#fde68a">
      <div class="card-body p-3" style="font-size:12.5px;color:#92400e">
        <i class="bi bi-lightbulb-fill" style="color:#d97706"></i>
        <strong>Tip:</strong> If an Application ID already exists, its record will be <em>updated</em> and all sent-flags reset. New IDs create fresh cases.
      </div>
    </div>
  </div>
</div>
"""
    scripts = """<script>
var inp = document.getElementById('csvInput');
var lbl = document.getElementById('fileLabel');
var zone = document.getElementById('uploadZone');
inp.addEventListener('change', function(){
  lbl.textContent = this.files[0] ? this.files[0].name : 'No file selected';
});
zone.addEventListener('dragover', function(e){ e.preventDefault(); zone.classList.add('drag'); });
zone.addEventListener('dragleave', function(){ zone.classList.remove('drag'); });
zone.addEventListener('drop', function(e){
  e.preventDefault(); zone.classList.remove('drag');
  var f = e.dataTransfer.files[0];
  if(f){ inp.files = e.dataTransfer.files; lbl.textContent = f.name; }
});
document.getElementById('uploadForm').addEventListener('submit', function(){
  var btn = this.querySelector('button[type=submit]');
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing…';
  btn.disabled = true;
});
</script>"""
    return render_page(content, scripts, active_page="bulk",
                       page_title="Bulk Upload",
                       page_crumb='<a href="/">Dashboard</a> / Bulk Upload')


_TEMPLATE_COLS = ["Application_ID", "Organisation_Name", "Programme_Name", "Stage_Name",
                  "Date_of_Stage_Change", "Action_Owner_Name", "Action_Owner_Email", "Program_Officer_Email"]
_TEMPLATE_EXAMPLE = ["APP-001", "Sample Hospital", "NABH Full Accreditation Hospitals",
                     "Application In Progress", date.today().isoformat(),
                     "Mr. Applicant", "applicant@example.com", "po@qci.org.in"]


@app.route("/csv-template")
@login_required
def csv_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_TEMPLATE_COLS)
    writer.writerow(_TEMPLATE_EXAMPLE)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=case_upload_template.csv"},
    )


@app.route("/xlsx-template")
@login_required
def xlsx_template():
    if not HAS_XLSX:
        flash("openpyxl not installed. Run: pip3 install openpyxl", "error")
        return redirect(url_for("bulk_upload"))
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Cases"
    ws.append(_TEMPLATE_COLS)
    ws.append(_TEMPLATE_EXAMPLE)
    # Style header row
    header_fill = PatternFill("solid", fgColor="1A3557")
    header_font = Font(bold=True, color="FFFFFF", size=11)
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
    # Style example row
    for cell in ws[2]:
        cell.font = Font(italic=True, color="888888")
    # Column widths
    widths = [16, 24, 36, 30, 22, 22, 28, 28]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = w
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=case_upload_template.xlsx"},
    )


@app.route("/edit-case/<int:case_id>", methods=["GET", "POST"])
@login_required
def edit_case(case_id):
    conn = get_db()
    case = conn.execute("SELECT * FROM case_tracking WHERE id=?", (case_id,)).fetchone()
    if not case:
        conn.close()
        flash("Case not found.", "error")
        return redirect(url_for("dashboard"))
    case = dict(case)

    bid = user_board_id()
    if bid is not None:
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes WHERE board_id=? ORDER BY programme_name", (bid,)
        ).fetchall()]
    else:
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes ORDER BY programme_name"
        ).fetchall()]
    conn.close()

    if request.method == "POST":
        data = {
            "application_id":     case["application_id"],
            "organisation_name":  request.form["organisation_name"].strip(),
            "programme_name":     request.form["programme_name"].strip(),
            "stage_name":         request.form["stage_name"].strip(),
            "stage_start_date":   request.form["stage_start_date"].strip(),
            "action_owner_name":  request.form["action_owner_name"].strip(),
            "action_owner_email": request.form["action_owner_email"].strip(),
            "program_officer_email": request.form["program_officer_email"].strip(),
            "cc_emails":          request.form.get("cc_emails", "").strip(),
            "suppress_until":     request.form.get("suppress_until", "").strip() or None,
        }
        try:
            data["_changed_by"] = session.get("full_name") or session.get("username", "")
            upsert_case(data)
            flash(f"Case {case['application_id']} updated.", "success")
            return redirect(url_for("dashboard"))
        except ValueError as e:
            flash(str(e), "error")

    prog_opts = "".join(
        f'<option value="{p}" {"selected" if p==case["programme_name"] else ""}>{p}</option>'
        for p in programmes
    )
    content = f"""
<div style="max-width:720px;margin:0 auto">
  <div class="card form-card">
    <div class="card-header d-flex align-items-center gap-3">
      <i class="bi bi-pencil-square" style="color:#d97706;font-size:18px"></i>
      <div>
        <div>Edit Case</div>
        <div style="font-size:11px;font-weight:400;color:#94a3b8">{case['application_id']} · {case['organisation_name']}</div>
      </div>
    </div>
    <div class="card-body p-4">
      <form method="post" id="editForm">

        <div class="form-section-title">Programme &amp; Stage</div>
        <div class="row g-3 mb-3">
          <div class="col-md-6">
            <label class="form-label">Programme</label>
            <select class="form-select" name="programme_name" id="progSelect" required>
              {prog_opts}
            </select>
          </div>
          <div class="col-md-6">
            <label class="form-label">Stage</label>
            <select class="form-select" name="stage_name" id="stageSelect" required>
              <option value="{case['current_stage']}">{case['current_stage']}</option>
            </select>
          </div>
        </div>

        <hr style="border-color:#f1f5f9;margin:20px 0">
        <div class="form-section-title">Application Info</div>
        <div class="row g-3 mb-3">
          <div class="col-md-6">
            <label class="form-label">Organisation Name</label>
            <input type="text" class="form-control" name="organisation_name"
                   value="{case['organisation_name']}" required>
          </div>
          <div class="col-md-6">
            <label class="form-label">Date of Stage Change</label>
            <input type="date" class="form-control" name="stage_start_date"
                   value="{case['stage_start_date']}" required>
          </div>
        </div>

        <hr style="border-color:#f1f5f9;margin:20px 0">
        <div class="form-section-title">People</div>
        <div class="mb-3">
          <label class="form-label">Program Officer Email</label>
          <input type="email" class="form-control" name="program_officer_email"
                 value="{case['program_officer_email'] or ''}" required>
        </div>
        <div class="row g-3 mb-4">
          <div class="col-md-6">
            <label class="form-label">Action Owner Name</label>
            <input type="text" class="form-control" name="action_owner_name"
                   value="{case['action_owner_name'] or ''}" required>
          </div>
          <div class="col-md-6">
            <label class="form-label">Action Owner Email</label>
            <input type="email" class="form-control" name="action_owner_email"
                   value="{case['action_owner_email'] or ''}" required>
          </div>
        </div>

        <hr style="border-color:#f1f5f9;margin:20px 0">
        <div class="form-section-title">Notifications</div>
        <div class="mb-3">
          <label class="form-label">CC Emails <span style="color:#94a3b8;font-size:11px">(comma-separated — get copied on all notifications)</span></label>
          <input type="text" class="form-control" name="cc_emails"
                 value="{case.get('cc_emails') or ''}" placeholder="manager@org.com, supervisor@org.com">
        </div>
        <div class="mb-3">
          <label class="form-label">Suppress Notifications Until <span style="color:#94a3b8;font-size:11px">(optional — pause all emails until this date)</span></label>
          <input type="date" class="form-control" name="suppress_until"
                 value="{case.get('suppress_until') or ''}">
        </div>

        <div class="alert" style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;font-size:13px;color:#92400e;padding:10px 14px">
          <i class="bi bi-arrow-clockwise"></i> Saving will <strong>reset</strong> all sent-flags (R1, R2, Overdue) and the overdue counter for this case.
        </div>

        <div class="d-flex gap-2 mt-3">
          <button type="submit" class="btn btn-warning flex-grow-1" style="padding:10px">
            <i class="bi bi-check2"></i> Save Changes
          </button>
          <a href="/" class="btn btn-outline-secondary" style="padding:10px 20px">Cancel</a>
        </div>
      </form>
    </div>
  </div>
</div>
"""
    scripts = f"""<script>
var _currentStage = "{case['current_stage']}";
function loadStages(prog, selectVal){{
  var sel = document.getElementById('stageSelect');
  fetch('/api/stages?programme='+encodeURIComponent(prog))
    .then(r=>r.json())
    .then(data=>{{
      sel.innerHTML = data.map(s=>'<option value="'+s.stage_name+'"'+(s.stage_name===selectVal?' selected':'')+'>'+s.stage_name+'</option>').join('');
    }});
}}
document.getElementById('progSelect').addEventListener('change', function(){{
  loadStages(this.value, '');
}});
loadStages("{case['programme_name']}", _currentStage);
</script>"""
    return render_page(content, scripts, active_page="",
                       page_title="Edit Case",
                       page_crumb=f'<a href="/">Dashboard</a> / Edit {case["application_id"]}')


@app.route("/delete-case/<int:case_id>")
@login_required
def delete_case(case_id):
    conn = get_db()
    row = conn.execute("SELECT application_id FROM case_tracking WHERE id=?", (case_id,)).fetchone()
    if row:
        conn.execute("DELETE FROM case_tracking WHERE id=?", (case_id,))
        conn.commit()
        flash(f"Case {row['application_id']} closed.", "success")
        conn.close()
        log_audit("case_closed", row["application_id"], "Case closed/removed",
                  session.get("full_name") or session.get("username", ""),
                  user_board_id())
    else:
        conn.close()
    return redirect(url_for("dashboard"))


@app.route("/settings", methods=["GET", "POST"])
@board_admin_required
def settings():
    conn = get_db()
    msg = ""

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_board":
            if session.get("role") != "super_admin":
                flash("Only Super Admin can add boards.", "error")
            else:
                bname = request.form.get("board_name", "").strip()
                if bname:
                    try:
                        conn.execute("INSERT INTO boards (board_name) VALUES (?)", (bname,))
                        conn.commit()
                        flash(f"Board '{bname}' added.", "success")
                    except Exception as e:
                        flash(f"Error: {e}", "error")

        elif action == "add_programme":
            pname = request.form.get("programme_name", "").strip()
            board_id = request.form.get("board_id", "")
            if not pname or not board_id:
                flash("Programme name and board are required.", "error")
            else:
                board_id = int(board_id)
                if session.get("role") == "board_admin" and board_id != session.get("board_id"):
                    flash("Cannot add programme to another board.", "error")
                else:
                    try:
                        conn.execute(
                            "INSERT INTO programmes (programme_name, board_id) VALUES (?,?)",
                            (pname, board_id)
                        )
                        conn.commit()
                        flash(f"Programme '{pname}' added.", "success")
                    except Exception as e:
                        flash(f"Error: {e}", "error")

        elif action == "add_stage":
            pname = request.form.get("programme_name", "").strip()
            sname = request.form.get("stage_name", "").strip()
            if not pname or not sname:
                flash("Programme and stage name are required.", "error")
            else:
                # Determine board_id from programme
                prog_row = conn.execute(
                    "SELECT board_id FROM programmes WHERE programme_name=?", (pname,)
                ).fetchone()
                prog_board_id = prog_row[0] if prog_row else None
                if session.get("role") == "board_admin" and prog_board_id != session.get("board_id"):
                    flash("Cannot add stages to a programme in another board.", "error")
                else:
                    try:
                        conn.execute(
                            """INSERT INTO programme_config
                               (programme_name,stage_name,stage_order,tat_days,reminder1_day,
                                reminder2_day,owner_type,overdue_interval_days,is_milestone,board_id)
                               VALUES (?,?,?,?,?,?,?,?,?,?)""",
                            (pname, sname,
                             int(request.form.get("stage_order", 1)),
                             int(request.form.get("tat_days", 0)),
                             int(request.form.get("reminder1_day", 0)),
                             int(request.form.get("reminder2_day", 0)),
                             request.form.get("owner_type") or None,
                             int(request.form.get("overdue_interval_days", 3)),
                             1 if request.form.get("is_milestone") else 0,
                             prog_board_id),
                        )
                        conn.commit()
                        flash(f"Stage '{sname}' added to {pname}.", "success")
                    except Exception as e:
                        flash(f"Error: {e}", "error")

        elif action == "update_schedule":
            if session.get("role") != "super_admin":
                flash("Only Super Admin can change the schedule.", "error")
            else:
                raw = request.form.get("schedule_time", "08:00")
                try:
                    parts = raw.split(":")
                    sh, sm = int(parts[0]), int(parts[1])
                    set_app_setting("scheduler_hour",   str(sh))
                    set_app_setting("scheduler_minute", str(sm))
                    scheduler.reschedule_job(
                        "daily_check", trigger="cron",
                        hour=sh, minute=sm
                    )
                    flash(f"Daily check rescheduled to {sh:02d}:{sm:02d} IST.", "success")
                except Exception as e:
                    flash(f"Error updating schedule: {e}", "error")

        elif action == "update_sender":
            prog = request.form["programme_name"].strip()
            email = request.form["sender_email"].strip()
            password = request.form.get("sender_password", "").strip()
            smtp_host = request.form.get("smtp_host", "smtp.gmail.com").strip()
            smtp_port = int(request.form.get("smtp_port", 587) or 587)
            enc_pw = encrypt_str(password) if password else None
            if enc_pw:
                conn.execute(
                    "UPDATE programme_config SET sender_email=?, sender_password=?, smtp_host=?, smtp_port=? WHERE programme_name=?",
                    (email, enc_pw, smtp_host, smtp_port, prog),
                )
            else:
                conn.execute(
                    "UPDATE programme_config SET sender_email=?, smtp_host=?, smtp_port=? WHERE programme_name=?",
                    (email, smtp_host, smtp_port, prog),
                )
            conn.commit()
            flash(f"Sender credentials updated for {prog}.", "success")

    # Build Board → Programme → Stage hierarchy
    bid = user_board_id()
    all_boards = [dict(r) for r in conn.execute(
        "SELECT * FROM boards ORDER BY board_name"
    ).fetchall()]

    # Filter boards visible to this user
    if bid is not None:
        visible_boards = [b for b in all_boards if b["id"] == bid]
    else:
        visible_boards = all_boards

    # Load programmes per board
    board_programmes = {}
    for b in visible_boards:
        board_programmes[b["id"]] = [dict(r) for r in conn.execute(
            "SELECT * FROM programmes WHERE board_id=? ORDER BY programme_name", (b["id"],)
        ).fetchall()]

    # Load stages per programme
    prog_stages = {}
    for b in visible_boards:
        for p in board_programmes[b["id"]]:
            rows = conn.execute(
                "SELECT * FROM programme_config WHERE programme_name=? ORDER BY stage_order",
                (p["programme_name"],)
            ).fetchall()
            prog_stages[p["programme_name"]] = [dict(r) for r in rows]
            # Merge sender info from first row
            first = prog_stages[p["programme_name"]]
            p["sender_email"] = first[0]["sender_email"] if first else None
            p["smtp_host"] = first[0].get("smtp_host", "smtp.gmail.com") if first else "smtp.gmail.com"
            p["smtp_port"] = first[0].get("smtp_port", 587) if first else 587

    conn.close()

    # Programmes list for "Add Stage" dropdown (scoped to user's boards)
    all_prog_names = []
    for b in visible_boards:
        for p in board_programmes[b["id"]]:
            all_prog_names.append(p["programme_name"])

    # Build accordion HTML: Board → Programme → Stages
    board_sections = ""
    for b in visible_boards:
        bid_safe = str(b["id"])
        prog_count = len(board_programmes[b["id"]])
        prog_inner = ""
        for p in board_programmes[b["id"]]:
            pname = p["programme_name"]
            pid_safe = pname.replace(" ", "_").replace("/", "_")
            stages = prog_stages.get(pname, [])
            sender_status = p.get("sender_email") or ""
            credential_badge = (
                f'<span class="pill pill-ok" style="font-size:11px"><i class="bi bi-shield-check"></i> {sender_status}</span>'
                if sender_status else
                '<span class="pill pill-warn" style="font-size:11px"><i class="bi bi-exclamation-circle"></i> No sender configured</span>'
            )
            stages_rows = "".join(
                f"""<tr>
                  <td style="color:#94a3b8;font-size:12px">{s['stage_order']}</td>
                  <td style="font-weight:500">{'<i class="bi bi-flag-fill" style="color:#7c3aed;font-size:11px"></i> ' if s['is_milestone'] else ''}{s['stage_name']}</td>
                  <td style="text-align:center">{s['tat_days'] or '—'}</td>
                  <td style="text-align:center;color:#2563eb">{s['reminder1_day'] or '—'}</td>
                  <td style="text-align:center;color:#d97706">{s['reminder2_day'] or '—'}</td>
                  <td>{s['owner_type'] or '—'}</td>
                  <td style="text-align:center">{s['overdue_interval_days']}</td>
                </tr>"""
                for s in stages
            )
            th_center = 'style="text-align:center"'
            if stages:
                stages_table_html = (
                    '<div style="overflow-x:auto"><table class="data-table"><thead><tr>'
                    '<th>#</th><th>Stage Name</th>'
                    f'<th {th_center}>TAT</th><th {th_center}>R1 Day</th>'
                    f'<th {th_center}>R2 Day</th><th>Owner</th><th {th_center}>OD Interval</th>'
                    '</tr></thead><tbody>' + stages_rows + '</tbody></table></div>'
                )
            else:
                stages_table_html = '<div style="padding:16px 20px;color:#94a3b8;font-size:13px">No stages configured yet.</div>'

            prog_inner += f"""
<div class="accordion-item" style="border:1px solid #e2e8f0;border-radius:8px;margin-bottom:8px;overflow:hidden">
  <h2 class="accordion-header">
    <button class="accordion-button collapsed py-2" type="button" data-bs-toggle="collapse"
            data-bs-target="#prog_{pid_safe}" style="background:#f8fafc;font-size:14px">
      <div class="d-flex align-items-center gap-3 w-100 me-3">
        <i class="bi bi-list-task" style="color:#7c3aed"></i>
        <span style="font-weight:600">{pname}</span>
        <span>{credential_badge}</span>
        <span class="ms-auto" style="font-size:12px;color:#94a3b8">{len(stages)} stages</span>
      </div>
    </button>
  </h2>
  <div id="prog_{pid_safe}" class="accordion-collapse collapse">
    <div class="accordion-body p-0">
      {stages_table_html}
      <div style="padding:16px 20px;background:#f8fafc;border-top:1px solid #e2e8f0">
        <div style="font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px">
          <i class="bi bi-envelope-at"></i> Outbound Email Settings
        </div>
        <form method="post" class="row g-2 align-items-end">
          <input type="hidden" name="action" value="update_sender">
          <input type="hidden" name="programme_name" value="{pname}">
          <div class="col-md-4">
            <label class="form-label" style="font-size:12px">Sender Email</label>
            <input type="email" class="form-control form-control-sm" name="sender_email"
                   value="{p.get('sender_email') or ''}" placeholder="notifications@yourdomain.com">
          </div>
          <div class="col-md-3">
            <label class="form-label" style="font-size:12px">Password <span style="color:#94a3b8">(blank = keep)</span></label>
            <input type="password" class="form-control form-control-sm" name="sender_password"
                   placeholder="••••••••" autocomplete="new-password">
          </div>
          <div class="col-md-3">
            <label class="form-label" style="font-size:12px">SMTP Host</label>
            <input type="text" class="form-control form-control-sm" name="smtp_host"
                   value="{p.get('smtp_host','smtp.gmail.com')}" placeholder="smtp.gmail.com">
          </div>
          <div class="col-md-1">
            <label class="form-label" style="font-size:12px">Port</label>
            <input type="number" class="form-control form-control-sm" name="smtp_port"
                   value="{p.get('smtp_port', 587)}" placeholder="587">
          </div>
          <div class="col-auto">
            <button class="btn btn-sm btn-primary" type="submit">Save</button>
          </div>
        </form>
        <div style="font-size:11px;color:#94a3b8;margin-top:6px">
          Gmail: smtp.gmail.com:587 · Outlook: smtp.office365.com:587 · Port 465 = SSL
        </div>
      </div>
    </div>
  </div>
</div>"""

        board_sections += f"""
<div class="accordion-item" style="border:2px solid #e2e8f0;border-radius:12px;margin-bottom:16px;overflow:hidden">
  <h2 class="accordion-header">
    <button class="accordion-button" type="button" data-bs-toggle="collapse"
            data-bs-target="#board_{bid_safe}" style="background:linear-gradient(135deg,#003356,#0094ca);color:#fff;font-weight:700;font-size:15px">
      <div class="d-flex align-items-center gap-3 w-100 me-3">
        <i class="bi bi-building" style="font-size:18px"></i>
        <span>{b['board_name']}</span>
        <span class="ms-auto" style="font-size:12px;opacity:.8">{prog_count} programme{"s" if prog_count != 1 else ""}</span>
      </div>
    </button>
  </h2>
  <div id="board_{bid_safe}" class="accordion-collapse collapse show">
    <div class="accordion-body" style="background:#fafbfc;padding:16px">
      <div class="accordion" id="progAccordion_{bid_safe}">
        {prog_inner if prog_inner else '<div style="color:#94a3b8;font-size:13px;padding:8px">No programmes in this board yet.</div>'}
      </div>
    </div>
  </div>
</div>"""

    # Board options for add_programme form
    board_opts = "".join(
        f'<option value="{b["id"]}">{b["board_name"]}</option>'
        for b in visible_boards
    )
    # Programme options for add_stage form
    prog_opts = "".join(
        f'<option value="{pn}">{pn}</option>'
        for pn in all_prog_names
    )

    is_super = session.get("role") == "super_admin"

    # Current schedule for display
    cur_hour   = int(get_app_setting("scheduler_hour",   "8"))
    cur_minute = int(get_app_setting("scheduler_minute", "0"))
    cur_time_val = f"{cur_hour:02d}:{cur_minute:02d}"

    scheduler_html = f"""
      <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" style="cursor:pointer"
             onclick="togglePanel('schedBody')">
          <span><i class="bi bi-clock" style="color:#0891b2"></i> Scheduler Settings</span>
          <i class="bi bi-chevron-down" style="color:#94a3b8"></i>
        </div>
        <div id="schedBody" style="display:none">
          <div class="card-body p-3">
            <form method="post">
              <input type="hidden" name="action" value="update_schedule">
              <div class="mb-2">
                <label class="form-label" style="font-size:12px">
                  Daily run time <span style="color:#94a3b8">(IST, 24-hr)</span>
                </label>
                <input type="time" class="form-control form-control-sm"
                       name="schedule_time" value="{cur_time_val}" required>
              </div>
              <div style="font-size:11px;color:#94a3b8;margin-bottom:10px">
                Currently set to <strong>{cur_hour:02d}:{cur_minute:02d} IST</strong>.
                Change takes effect immediately — no restart needed.
              </div>
              <button class="btn btn-sm btn-primary w-100" type="submit">Update Schedule</button>
            </form>
          </div>
        </div>
      </div>""" if is_super else ""

    add_board_html = f"""
      <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" style="cursor:pointer"
             onclick="togglePanel('addBoardBody')">
          <span><i class="bi bi-building-add" style="color:#7c3aed"></i> Add New Board</span>
          <i class="bi bi-chevron-down" style="color:#94a3b8"></i>
        </div>
        <div id="addBoardBody" style="display:none">
          <div class="card-body p-3">
            <form method="post" class="row g-2 align-items-end">
              <input type="hidden" name="action" value="add_board">
              <div class="col">
                <label class="form-label" style="font-size:12px">Board Name</label>
                <input type="text" class="form-control form-control-sm" name="board_name"
                       required placeholder="e.g. NABH">
              </div>
              <div class="col-auto">
                <button class="btn btn-sm btn-primary" type="submit">Create Board</button>
              </div>
            </form>
          </div>
        </div>
      </div>""" if is_super else ""

    content = f"""
<div class="row g-4">
  <div class="col-lg-4">
    <!-- Action panels -->
    {scheduler_html}
    {add_board_html}

    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" style="cursor:pointer"
           onclick="togglePanel('addProgBody')">
        <span><i class="bi bi-folder-plus" style="color:#2563eb"></i> Add New Programme</span>
        <i class="bi bi-chevron-down" style="color:#94a3b8"></i>
      </div>
      <div id="addProgBody" style="display:none">
        <div class="card-body p-3">
          <form method="post">
            <input type="hidden" name="action" value="add_programme">
            <div class="mb-2">
              <label class="form-label" style="font-size:12px">Board</label>
              <select class="form-select form-select-sm" name="board_id" required>
                <option value="">— select —</option>
                {board_opts}
              </select>
            </div>
            <div class="mb-2">
              <label class="form-label" style="font-size:12px">Programme Name</label>
              <input type="text" class="form-control form-control-sm" name="programme_name"
                     required placeholder="e.g. NABH Full Accreditation Hospitals">
            </div>
            <button class="btn btn-sm btn-primary w-100" type="submit">Create Programme</button>
          </form>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center" style="cursor:pointer"
           onclick="togglePanel('addStageBody')">
        <span><i class="bi bi-plus-circle" style="color:#059669"></i> Add New Stage</span>
        <i class="bi bi-chevron-down" style="color:#94a3b8"></i>
      </div>
      <div id="addStageBody" style="display:none">
        <div class="card-body p-3">
          <form method="post">
            <input type="hidden" name="action" value="add_stage">
            <div class="mb-2">
              <label class="form-label" style="font-size:12px">Programme</label>
              <select class="form-select form-select-sm" name="programme_name" required>
                <option value="">— select —</option>
                {prog_opts}
              </select>
            </div>
            <div class="mb-2">
              <label class="form-label" style="font-size:12px">Stage Name</label>
              <input type="text" class="form-control form-control-sm" name="stage_name" required>
            </div>
            <div class="row g-2 mb-2">
              <div class="col-4">
                <label class="form-label" style="font-size:12px">Order #</label>
                <input type="number" class="form-control form-control-sm" name="stage_order" value="1" min="1">
              </div>
              <div class="col-4">
                <label class="form-label" style="font-size:12px">TAT Days</label>
                <input type="number" class="form-control form-control-sm" name="tat_days" value="0" min="0">
              </div>
              <div class="col-4">
                <label class="form-label" style="font-size:12px">OD Interval</label>
                <input type="number" class="form-control form-control-sm" name="overdue_interval_days" value="3" min="1">
              </div>
            </div>
            <div class="row g-2 mb-2">
              <div class="col-6">
                <label class="form-label" style="font-size:12px">R1 Day</label>
                <input type="number" class="form-control form-control-sm" name="reminder1_day" value="0" min="0">
              </div>
              <div class="col-6">
                <label class="form-label" style="font-size:12px">R2 Day</label>
                <input type="number" class="form-control form-control-sm" name="reminder2_day" value="0" min="0">
              </div>
            </div>
            <div class="mb-2">
              <label class="form-label" style="font-size:12px">Owner Type</label>
              <select class="form-select form-select-sm" name="owner_type">
                <option value="">—</option>
                <option>Applicant</option>
                <option>Assessor</option>
                <option>Program Officer</option>
              </select>
            </div>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" name="is_milestone" id="msCheck">
              <label class="form-check-label" style="font-size:12px" for="msCheck">Milestone stage (no emails)</label>
            </div>
            <button class="btn btn-sm btn-success w-100" type="submit">Add Stage</button>
          </form>
        </div>
      </div>
    </div>
  </div>

  <div class="col-lg-8">
    <!-- Board → Programme → Stage accordion -->
    <div class="accordion" id="boardAccordion">
      {board_sections if board_sections else '<div class="card"><div class="card-body text-center" style="color:#94a3b8;padding:40px">No boards configured yet.</div></div>'}
    </div>
  </div>
</div>
"""
    scripts = """<script>
function togglePanel(id){
  var el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? '' : 'none';
}
</script>"""
    return render_page(content, scripts, active_page="settings",
                       page_title="Programme Settings")


@app.route("/templates", methods=["GET", "POST"])
@board_admin_required
def email_templates_page():
    conn = get_db()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "save":
            tmpl_id = request.form.get("id")
            if tmpl_id:
                conn.execute(
                    "UPDATE email_templates SET subject_line=?, email_body=? WHERE id=?",
                    (request.form["subject_line"], request.form["email_body"], tmpl_id),
                )
            else:
                conn.execute(
                    "INSERT INTO email_templates "
                    "(programme_name, notification_type, subject_line, email_body) VALUES (?,?,?,?) "
                    "ON CONFLICT(programme_name, notification_type) "
                    "DO UPDATE SET subject_line=EXCLUDED.subject_line, email_body=EXCLUDED.email_body",
                    (request.form["programme_name"], request.form["notification_type"],
                     request.form["subject_line"], request.form["email_body"]),
                )
            conn.commit()
            flash("Template saved.", "success")

    et_bid = user_board_id()
    if et_bid is not None:
        templates = [dict(r) for r in conn.execute(
            "SELECT * FROM email_templates WHERE board_id=? ORDER BY programme_name, notification_type",
            (et_bid,)
        ).fetchall()]
        programmes = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes WHERE board_id=? ORDER BY programme_name",
            (et_bid,)
        ).fetchall()]
    else:
        templates = [dict(r) for r in conn.execute(
            "SELECT * FROM email_templates ORDER BY programme_name, notification_type"
        ).fetchall()]
        programmes = [r[0] for r in conn.execute(
            "SELECT DISTINCT programme_name FROM programme_config ORDER BY programme_name"
        ).fetchall()]
    conn.close()

    PLACEHOLDER_HELP = (
        "{{Organisation_Name}}, {{Stage_Name}}, {{Action_Owner_Name}}, "
        "{{Days_Remaining}}, {{TAT_Days}}, {{Stage_Start_Date}}, "
        "{{Programme_Name}}, {{Followup_Count}}, {{PO_Name}}"
    )

    TYPE_META = {
        "R1":      ("bi-bell",            "#2563eb", "#dbeafe", "Friendly reminder — sent at R1 day"),
        "R2":      ("bi-clock-history",   "#d97706", "#fef3c7", "Urgent reminder — sent at R2 day"),
        "Overdue": ("bi-exclamation-octagon","#dc2626","#fee2e2","TAT breached — sent when overdue"),
        "Followup":("bi-arrow-clockwise", "#7c3aed", "#ede9fe", "Repeated follow-up — every overdue interval"),
    }

    tmpl_forms = ""
    for t in templates:
        icon, color, bg, desc = TYPE_META.get(t['notification_type'], ("bi-envelope","#64748b","#f1f5f9",""))
        safe_body = t['email_body'].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        safe_subject = t['subject_line'].replace('"','&quot;')
        tmpl_forms += f"""
<div class="card mb-3">
  <div class="card-header d-flex align-items-center gap-3">
    <div style="width:34px;height:34px;border-radius:8px;background:{bg};color:{color};
                display:flex;align-items:center;justify-content:center;font-size:16px">
      <i class="bi {icon}"></i>
    </div>
    <div>
      <div style="font-weight:600">{t['notification_type']} — {t['programme_name']}</div>
      <div style="font-size:12px;color:#94a3b8">{desc}</div>
    </div>
  </div>
  <div class="card-body p-4">
    <form method="post">
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="{t['id']}">
      <div class="mb-3">
        <label class="form-label">Subject Line</label>
        <input type="text" class="form-control" name="subject_line" value="{safe_subject}">
      </div>
      <div class="mb-3">
        <label class="form-label">Email Body</label>
        <textarea class="form-control" name="email_body" rows="10"
                  style="font-family:monospace;font-size:13px">{safe_body}</textarea>
      </div>
      <button type="submit" class="btn btn-sm btn-primary">
        <i class="bi bi-save"></i> Save Template
      </button>
    </form>
  </div>
</div>"""

    prog_opts = "".join(f'<option value="{p}">{p}</option>' for p in programmes)

    ph_chips = " ".join(
        f'<span class="ph-chip" onclick="insertPH(this.textContent)">{{{{{p}}}}}</span>'
        for p in ["Organisation_Name","Stage_Name","Action_Owner_Name","Days_Remaining",
                  "TAT_Days","Stage_Start_Date","Programme_Name","Followup_Count","PO_Name"]
    )

    content = f"""
<div class="row g-4">
  <div class="col-xl-8">

    <!-- Placeholder reference -->
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px;margin-bottom:20px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#94a3b8;margin-bottom:8px">
        <i class="bi bi-braces"></i> Available Placeholders — click to copy
      </div>
      <div>{ph_chips}</div>
    </div>

    <!-- Existing templates -->
    {tmpl_forms}
  </div>

  <div class="col-xl-4">
    <div class="card" style="position:sticky;top:72px">
      <div class="card-header"><i class="bi bi-plus-circle" style="color:#059669"></i> Add New Template</div>
      <div class="card-body p-4">
        <form method="post">
          <input type="hidden" name="action" value="save">
          <div class="mb-3">
            <label class="form-label">Programme</label>
            <select class="form-select" name="programme_name" required>
              {prog_opts}
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Notification Type</label>
            <select class="form-select" name="notification_type" required>
              <option value="R1">R1 — Friendly Reminder</option>
              <option value="R2">R2 — Deadline Approaching</option>
              <option value="Overdue">Overdue — TAT Breached</option>
              <option value="Followup">Followup — Repeat Notice</option>
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Subject Line</label>
            <input type="text" class="form-control" name="subject_line" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Email Body</label>
            <textarea class="form-control" name="email_body" rows="10"
                      style="font-family:monospace;font-size:12px" required></textarea>
          </div>
          <button type="submit" class="btn btn-success w-100">Create Template</button>
        </form>
      </div>
    </div>
  </div>
</div>
"""
    scripts = """<script>
function insertPH(text){
  navigator.clipboard.writeText(text).then(function(){
    var t = document.createElement('div');
    t.className = 'toast qci-toast show align-items-center text-white bg-primary border-0';
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;min-width:220px';
    t.innerHTML = '<div class="d-flex"><div class="toast-body">Copied: '+text+'</div></div>';
    document.body.appendChild(t);
    setTimeout(function(){ t.remove(); }, 2000);
  });
}
</script>"""
    return render_page(content, scripts, active_page="templates",
                       page_title="Email Templates")


# ── Audit Log page ────────────────────────────────────────────────────────────
@app.route("/audit-log")
@board_admin_required
def audit_log_page():
    conn = get_db()
    bid = user_board_id()
    if bid is not None:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE board_id=? OR board_id IS NULL ORDER BY id DESC LIMIT 500",
            (bid,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
    conn.close()

    EVENT_ICONS = {
        "case_created": ("bi-plus-circle-fill", "#00984C"),
        "case_updated": ("bi-pencil-fill", "#0094ca"),
        "case_closed":  ("bi-x-circle-fill", "#dc2626"),
        "stage_change": ("bi-arrow-right-circle-fill", "#7c3aed"),
        "email_sent":   ("bi-envelope-check-fill", "#00984C"),
        "email_error":  ("bi-envelope-x-fill", "#dc2626"),
        "bulk_upload":  ("bi-upload", "#0094ca"),
        "bulk_advance": ("bi-fast-forward-fill", "#d97706"),
    }

    tbl_rows = ""
    for r in rows:
        r = dict(r)
        icon, clr = EVENT_ICONS.get(r["event_type"], ("bi-circle", "#94a3b8"))
        tbl_rows += f"""<tr>
  <td style="white-space:nowrap;font-size:12px;color:#64748b">{r['timestamp']}</td>
  <td><i class="bi {icon}" style="color:{clr};margin-right:4px"></i>
    <span style="font-size:12px;font-weight:600">{r['event_type'].replace('_',' ').title()}</span></td>
  <td style="font-weight:500">{r['application_id'] or '—'}</td>
  <td style="font-size:12.5px">{r['detail'] or ''}</td>
  <td style="font-size:12px;color:#94a3b8">{r['user_name'] or 'system'}</td>
</tr>"""

    content = f"""
<div class="card">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span><i class="bi bi-journal-text" style="color:var(--accent)"></i> Audit Log</span>
    <span style="font-size:12px;color:#94a3b8">Last 500 events</span>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table">
      <thead><tr><th>Timestamp</th><th>Event</th><th>Application</th><th>Detail</th><th>User</th></tr></thead>
      <tbody>{tbl_rows if tbl_rows else '<tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:40px">No audit events yet.</td></tr>'}</tbody>
    </table>
  </div>
</div>"""
    return render_page(content, active_page="audit", page_title="Audit Log")


# ── Case History page ─────────────────────────────────────────────────────────
@app.route("/case-history/<app_id>")
@login_required
def case_history(app_id):
    conn = get_db()
    transitions = [dict(r) for r in conn.execute(
        "SELECT * FROM stage_history WHERE application_id=? ORDER BY id ASC", (app_id,)
    ).fetchall()]
    audits = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log WHERE application_id=? ORDER BY id ASC", (app_id,)
    ).fetchall()]
    conn.close()

    timeline_html = ""
    for t in transitions:
        from_lbl = t["from_stage"] or '<em style="color:#94a3b8">New Case</em>'
        timeline_html += f"""
<div class="d-flex align-items-start gap-3 mb-3">
  <div style="width:12px;height:12px;border-radius:50%;background:#7c3aed;margin-top:4px;flex-shrink:0"></div>
  <div>
    <div style="font-size:13px"><span style="color:#94a3b8">{from_lbl}</span>
      <i class="bi bi-arrow-right" style="margin:0 6px;color:#7c3aed"></i>
      <strong>{t['to_stage']}</strong></div>
    <div style="font-size:11px;color:#94a3b8">{t['timestamp']} · by {t['changed_by'] or 'system'}</div>
  </div>
</div>"""

    audit_rows = ""
    for a in audits:
        audit_rows += f"""<tr>
  <td style="font-size:12px;color:#64748b">{a['timestamp']}</td>
  <td style="font-size:12.5px;font-weight:500">{a['event_type'].replace('_',' ').title()}</td>
  <td style="font-size:12.5px">{a['detail'] or ''}</td>
  <td style="font-size:12px;color:#94a3b8">{a['user_name'] or 'system'}</td>
</tr>"""

    content = f"""
<div class="row g-4" style="max-width:960px;margin:0 auto">
  <div class="col-lg-5">
    <div class="card">
      <div class="card-header"><i class="bi bi-signpost-split-fill" style="color:#7c3aed"></i> Stage Timeline</div>
      <div class="card-body">
        {timeline_html if timeline_html else '<div style="color:#94a3b8;font-size:13px">No stage transitions recorded yet.</div>'}
      </div>
    </div>
  </div>
  <div class="col-lg-7">
    <div class="card">
      <div class="card-header"><i class="bi bi-clock-history" style="color:var(--accent)"></i> Activity Log</div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>Time</th><th>Event</th><th>Detail</th><th>User</th></tr></thead>
          <tbody>{audit_rows if audit_rows else '<tr><td colspan="4" style="text-align:center;color:#94a3b8;padding:20px">No events.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>"""
    return render_page(content, active_page="dashboard", page_title=f"Case History — {app_id}",
                       page_crumb=f'<a href="/">Dashboard</a> / {app_id}')


# ── Email Preview / Test Send ─────────────────────────────────────────────────
@app.route("/email-preview", methods=["GET", "POST"])
@board_admin_required
def email_preview():
    conn = get_db()
    bid = user_board_id()
    if bid is not None:
        progs = [r[0] for r in conn.execute(
            "SELECT programme_name FROM programmes WHERE board_id=? ORDER BY programme_name", (bid,)
        ).fetchall()]
    else:
        progs = [r[0] for r in conn.execute(
            "SELECT DISTINCT programme_name FROM programme_config ORDER BY programme_name"
        ).fetchall()]

    preview_html = ""
    if request.method == "POST":
        action = request.form.get("action")
        programme = request.form.get("programme_name", "")
        ntype = request.form.get("notification_type", "R1")

        tmpl = conn.execute(
            "SELECT * FROM email_templates WHERE programme_name=? AND notification_type=?",
            (programme, ntype)
        ).fetchone()

        sample_ph = {
            "Organisation_Name": "Sample Hospital Ltd.",
            "Stage_Name": "DR In Progress",
            "Action_Owner_Name": "Dr. Sharma",
            "Days_Remaining": "5",
            "TAT_Days": "10",
            "Stage_Start_Date": date.today().strftime("%Y-%m-%d"),
            "Programme_Name": programme,
            "Followup_Count": "1",
            "PO_Name": session.get("full_name", "Program Officer"),
        }

        if tmpl:
            tmpl = dict(tmpl)
            subj = tmpl["subject_line"]
            body = tmpl["email_body"]
            for k, v in sample_ph.items():
                subj = subj.replace("{{" + k + "}}", str(v))
                body = body.replace("{{" + k + "}}", str(v))
        else:
            subj = f"[{ntype}] Reminder — Sample"
            body = "No template found for this programme/type."

        preview_html = f"""
<div class="card mt-3">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span><i class="bi bi-eye" style="color:#7c3aed"></i> Email Preview</span>
    <span class="pill pill-muted">{ntype}</span>
  </div>
  <div class="card-body">
    <div style="font-size:12px;color:#64748b;margin-bottom:4px">Subject:</div>
    <div style="font-weight:600;font-size:14px;margin-bottom:16px;padding:8px 12px;background:#f8fafc;border-radius:6px;border:1px solid var(--border)">{subj}</div>
    <div style="font-size:12px;color:#64748b;margin-bottom:4px">Body:</div>
    <div style="white-space:pre-wrap;font-size:13px;line-height:1.6;padding:16px;background:#fafbfc;border-radius:8px;border:1px solid var(--border)">{body}</div>
  </div>
</div>"""

        if action == "test_send":
            test_email = request.form.get("test_email", "").strip()
            if test_email and programme:
                cfg = conn.execute(
                    "SELECT sender_email, sender_password, smtp_host, smtp_port "
                    "FROM programme_config WHERE programme_name=? AND sender_email IS NOT NULL LIMIT 1",
                    (programme,)
                ).fetchone()
                if cfg and cfg["sender_email"]:
                    ok, err = send_notification(
                        programme, ntype, test_email, "",
                        cfg["sender_email"], decrypt_str(cfg["sender_password"]),
                        sample_ph, cfg["smtp_host"] or "smtp.gmail.com",
                        cfg["smtp_port"] or 587
                    )
                    if ok:
                        flash(f"Test email sent to {test_email}!", "success")
                    else:
                        flash(f"Send failed: {err}", "error")
                else:
                    flash("No sender credentials configured for this programme.", "error")
            else:
                flash("Enter a test email address.", "error")

    conn.close()

    prog_opts = "".join(f'<option value="{p}">{p}</option>' for p in progs)
    content = f"""
<div style="max-width:800px;margin:0 auto">
  <div class="card">
    <div class="card-header"><i class="bi bi-envelope-open" style="color:var(--accent)"></i> Email Preview &amp; Test Send</div>
    <div class="card-body p-4">
      <form method="post">
        <div class="row g-3 mb-3">
          <div class="col-md-5">
            <label class="form-label">Programme</label>
            <select class="form-select" name="programme_name" required>
              <option value="">— select —</option>
              {prog_opts}
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label">Notification Type</label>
            <select class="form-select" name="notification_type">
              <option value="R1">R1 — Reminder 1</option>
              <option value="R2">R2 — Reminder 2</option>
              <option value="OVERDUE">Overdue</option>
              <option value="FOLLOWUP">Follow-up</option>
            </select>
          </div>
          <div class="col-md-4">
            <label class="form-label">Test Email <span style="color:#94a3b8;font-size:11px">(for test send)</span></label>
            <input type="email" class="form-control" name="test_email" placeholder="your@email.com">
          </div>
        </div>
        <div class="d-flex gap-2">
          <button type="submit" name="action" value="preview" class="btn btn-primary">
            <i class="bi bi-eye"></i> Preview
          </button>
          <button type="submit" name="action" value="test_send" class="btn btn-success">
            <i class="bi bi-send"></i> Send Test Email
          </button>
        </div>
      </form>
      {preview_html}
      <div style="margin-top:16px;font-size:12px;color:#94a3b8">
        <i class="bi bi-info-circle"></i> Preview uses sample data. Test Send uses the programme's configured SMTP credentials.
      </div>
    </div>
  </div>
</div>"""
    return render_page(content, active_page="templates", page_title="Email Preview & Test")


# ── Bulk Stage Advance ────────────────────────────────────────────────────────
@app.route("/bulk-advance", methods=["GET", "POST"])
@login_required
def bulk_advance():
    conn = get_db()
    bid = user_board_id()

    if bid is not None:
        cases = [dict(r) for r in conn.execute(
            "SELECT * FROM case_tracking WHERE board_id=? ORDER BY programme_name, application_id", (bid,)
        ).fetchall()]
    else:
        cases = [dict(r) for r in conn.execute(
            "SELECT * FROM case_tracking ORDER BY programme_name, application_id"
        ).fetchall()]

    if request.method == "POST":
        selected_ids = request.form.getlist("case_ids")
        target_stage = request.form.get("target_stage", "").strip()
        new_start_date = request.form.get("new_start_date", date.today().strftime("%Y-%m-%d"))

        if not selected_ids or not target_stage:
            flash("Select cases and a target stage.", "error")
        else:
            advanced = 0
            errors = 0
            user_name = session.get("full_name") or session.get("username", "")
            for cid in selected_ids:
                case = conn.execute("SELECT * FROM case_tracking WHERE id=?", (cid,)).fetchone()
                if not case:
                    continue
                case = dict(case)
                # Find stage config
                cfg = conn.execute(
                    "SELECT * FROM programme_config WHERE programme_name=? AND stage_name=?",
                    (case["programme_name"], target_stage)
                ).fetchone()
                if not cfg:
                    errors += 1
                    continue
                old_stage = case["current_stage"]
                conn.execute(
                    """UPDATE case_tracking SET current_stage=?, stage_start_date=?,
                       tat_days=?, reminder1_day=?, reminder2_day=?, owner_type=?,
                       is_milestone=?, r1_sent=0, r2_sent=0, overdue_sent=0, overdue_count=0,
                       last_overdue_date=NULL WHERE id=?""",
                    (target_stage, new_start_date, cfg["tat_days"], cfg["reminder1_day"],
                     cfg["reminder2_day"], cfg["owner_type"], cfg["is_milestone"], cid)
                )
                advanced += 1
                log_stage_transition(case["application_id"], old_stage, target_stage,
                                     user_name, case.get("board_id"))
            conn.commit()
            log_audit("bulk_advance", None,
                      f"Advanced {advanced} cases to '{target_stage}'", user_name, bid)
            flash(f"{advanced} case(s) advanced to '{target_stage}'. {errors} error(s).", "success")
            conn.close()
            return redirect(url_for("bulk_advance"))

    conn.close()

    # Build case checkboxes grouped by programme
    prog_groups = {}
    for c in cases:
        pn = c["programme_name"]
        if pn not in prog_groups:
            prog_groups[pn] = []
        prog_groups[pn].append(c)

    case_list_html = ""
    for pn, pcases in prog_groups.items():
        rows = ""
        for c in pcases:
            rows += f"""<tr>
  <td><input type="checkbox" name="case_ids" value="{c['id']}" class="form-check-input case-cb"></td>
  <td class="id-cell">{c['application_id']}</td>
  <td>{c['organisation_name']}</td>
  <td>{c['current_stage']}</td>
  <td style="font-size:12px;color:#94a3b8">{c['stage_start_date']}</td>
</tr>"""
        case_list_html += f"""
<div class="mb-3">
  <div style="font-weight:600;font-size:13px;color:var(--navy);margin-bottom:6px">
    <i class="bi bi-folder2" style="color:var(--accent)"></i> {pn}
    <span style="font-size:11px;color:#94a3b8;font-weight:400;margin-left:6px">{len(pcases)} cases</span>
  </div>
  <table class="data-table">
    <thead><tr><th style="width:30px"><input type="checkbox" class="form-check-input" onclick="toggleGroup(this)"></th><th>App ID</th><th>Organisation</th><th>Current Stage</th><th>Start Date</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    content = f"""
<form method="post">
<div class="row g-4">
  <div class="col-lg-8">
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-fast-forward-fill" style="color:#d97706"></i> Select Cases to Advance</span>
        <span style="font-size:12px;color:#94a3b8" id="selCount">0 selected</span>
      </div>
      <div class="card-body p-3" style="max-height:600px;overflow-y:auto">
        {case_list_html if case_list_html else '<div style="text-align:center;color:#94a3b8;padding:40px">No cases found.</div>'}
      </div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="card" style="position:sticky;top:72px">
      <div class="card-header">Advance To</div>
      <div class="card-body p-3">
        <div class="mb-3">
          <label class="form-label" style="font-size:12px">Target Stage</label>
          <input type="text" class="form-control" name="target_stage" required
                 placeholder="e.g. Application Fee Paid">
          <div style="font-size:11px;color:#94a3b8;margin-top:4px">Must be a valid stage in the same programme</div>
        </div>
        <div class="mb-3">
          <label class="form-label" style="font-size:12px">New Start Date</label>
          <input type="date" class="form-control" name="new_start_date"
                 value="{date.today().strftime('%Y-%m-%d')}">
        </div>
        <button type="submit" class="btn btn-warning w-100">
          <i class="bi bi-fast-forward-fill"></i> Advance Selected Cases
        </button>
      </div>
    </div>
  </div>
</div>
</form>"""
    scripts = """<script>
function toggleGroup(el){
  var tbody = el.closest('table').querySelector('tbody');
  tbody.querySelectorAll('.case-cb').forEach(function(cb){ cb.checked = el.checked; });
  updateCount();
}
document.addEventListener('change', function(e){
  if(e.target.classList.contains('case-cb')) updateCount();
});
function updateCount(){
  var n = document.querySelectorAll('.case-cb:checked').length;
  document.getElementById('selCount').textContent = n + ' selected';
}
</script>"""
    return render_page(content, scripts, active_page="bulk_advance",
                       page_title="Bulk Stage Advance")


# ── Quick Stage Advance (POST from dashboard modal) ──────────────────────────
@app.route("/quick-advance", methods=["POST"])
@login_required
def quick_advance_post():
    case_id = request.form.get("case_id")
    target_stage = request.form.get("target_stage", "").strip()
    new_start_date = request.form.get("new_start_date", date.today().strftime("%Y-%m-%d"))
    suppress_until = request.form.get("suppress_until", "").strip() or None

    conn = get_db()
    case = conn.execute("SELECT * FROM case_tracking WHERE id=?", (case_id,)).fetchone()
    if not case:
        conn.close()
        flash("Case not found.", "error")
        return redirect(url_for("dashboard"))
    case = dict(case)
    cfg = conn.execute(
        "SELECT * FROM programme_config WHERE programme_name=? AND stage_name=?",
        (case["programme_name"], target_stage)
    ).fetchone()
    if not cfg:
        conn.close()
        flash(f"Stage '{target_stage}' not found in this programme.", "error")
        return redirect(url_for("dashboard"))

    old_stage = case["current_stage"]
    conn.execute(
        """UPDATE case_tracking SET current_stage=?, stage_start_date=?,
           tat_days=?, reminder1_day=?, reminder2_day=?, owner_type=?, is_milestone=?,
           r1_sent=0, r2_sent=0, overdue_sent=0, overdue_count=0, last_overdue_date=NULL,
           suppress_until=? WHERE id=?""",
        (target_stage, new_start_date, cfg["tat_days"], cfg["reminder1_day"],
         cfg["reminder2_day"], cfg["owner_type"], cfg["is_milestone"],
         suppress_until, case_id)
    )
    conn.commit()
    conn.close()
    user_name = session.get("full_name") or session.get("username", "")
    log_stage_transition(case["application_id"], old_stage, target_stage, user_name, case.get("board_id"))
    log_audit("stage_change", case["application_id"],
              f"Quick advance: {old_stage} → {target_stage}", user_name, case.get("board_id"))
    flash(f"{case['application_id']} advanced to '{target_stage}'.", "success")
    return redirect(url_for("dashboard"))


# ── Global Search ─────────────────────────────────────────────────────────────
@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    bid = user_board_id()
    results = []
    if q:
        conn = get_db()
        pattern = f"%{q}%"
        base = "SELECT * FROM case_tracking WHERE (application_id LIKE ? OR organisation_name LIKE ?)"
        params = [pattern, pattern]
        if bid is not None:
            base += " AND board_id=?"
            params.append(bid)
        base += " LIMIT 50"
        results = [dict(r) for r in conn.execute(base, params).fetchall()]
        conn.close()

    today = date.today()
    for c in results:
        c["days_elapsed"] = working_days_elapsed(c["stage_start_date"], today)

    rows = ""
    for c in results:
        tat = c["tat_days"]
        elapsed = c["days_elapsed"]
        if tat > 0 and elapsed >= tat:
            badge = f'<span class="pill pill-danger">Overdue·{elapsed}d</span>'
        elif tat > 0 and elapsed >= c.get("reminder2_day", 0):
            badge = f'<span class="pill pill-warn">At Risk·{elapsed}d</span>'
        else:
            badge = f'<span class="pill pill-ok">On Track·{elapsed}d</span>'
        rows += f"""<tr>
  <td class="id-cell">{c['application_id']}</td>
  <td>{c['organisation_name']}</td>
  <td style="font-size:12px;color:#64748b">{c['programme_name']}</td>
  <td>{c['current_stage']}</td>
  <td>{badge}</td>
  <td><a href="/edit-case/{c['id']}" class="btn btn-sm btn-action btn-outline-primary me-1">Edit</a>
      <a href="/case-history/{c['application_id']}" class="btn btn-sm btn-action btn-outline-secondary">History</a></td>
</tr>"""

    content = f"""
<div class="card">
  <div class="card-header">
    <form method="get" class="d-flex gap-2 align-items-center">
      <input type="text" class="form-control" name="q" value="{q}" placeholder="Search by Application ID or Organisation…" style="max-width:400px">
      <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Search</button>
    </form>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table">
      <thead><tr><th>App ID</th><th>Organisation</th><th>Programme</th><th>Stage</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>
        {rows if rows else ('<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:40px">' +
          ('No results for "' + q + '"' if q else 'Enter a search term above.') + '</td></tr>')}
      </tbody>
    </table>
  </div>
</div>"""
    return render_page(content, active_page="search", page_title="Search Cases",
                       page_crumb=f"Search: {q}" if q else "Search")


# ── Analytics / Reports Hub ───────────────────────────────────────────────────
@app.route("/reports")
@login_required
def reports():
    conn = get_db()
    bid = user_board_id()
    today = date.today()

    if bid is not None:
        cases = [dict(r) for r in conn.execute(
            "SELECT * FROM case_tracking WHERE board_id=?", (bid,)
        ).fetchall()]
        history = [dict(r) for r in conn.execute(
            "SELECT * FROM stage_history WHERE board_id=? ORDER BY timestamp DESC", (bid,)
        ).fetchall()]
    else:
        cases = [dict(r) for r in conn.execute("SELECT * FROM case_tracking").fetchall()]
        history = [dict(r) for r in conn.execute(
            "SELECT * FROM stage_history ORDER BY timestamp DESC"
        ).fetchall()]
    conn.close()

    for c in cases:
        c["days_elapsed"] = working_days_elapsed(c["stage_start_date"], today)

    # ── TAT Breach Report ──
    breached = [c for c in cases if not c["is_milestone"] and c["tat_days"] > 0
                and c["days_elapsed"] >= c["tat_days"]]
    breach_rows = ""
    for c in sorted(breached, key=lambda x: x["days_elapsed"] - x["tat_days"], reverse=True):
        breach_days = c["days_elapsed"] - c["tat_days"]
        breach_rows += f"""<tr>
  <td class="id-cell">{c['application_id']}</td>
  <td>{c['organisation_name']}</td>
  <td style="font-size:12px">{c['programme_name']}</td>
  <td>{c['current_stage']}</td>
  <td style="text-align:center">{c['tat_days']}</td>
  <td style="text-align:center">{c['days_elapsed']}</td>
  <td style="text-align:center;font-weight:700;color:#dc2626">+{breach_days}d</td>
  <td style="font-size:12px;color:#94a3b8">{c['stage_start_date']}</td>
</tr>"""

    # ── Stage Funnel ──
    stage_counts = {}
    for c in cases:
        if not c["is_milestone"]:
            stage_counts[c["current_stage"]] = stage_counts.get(c["current_stage"], 0) + 1
    max_cnt = max(stage_counts.values()) if stage_counts else 1
    funnel_html = ""
    for stage, cnt in sorted(stage_counts.items(), key=lambda x: -x[1])[:20]:
        pct = int(cnt / max_cnt * 100)
        funnel_html += f"""
<div class="mb-2">
  <div class="d-flex justify-content-between" style="font-size:12px;margin-bottom:3px">
    <span style="font-weight:500;color:#1e293b">{stage}</span>
    <span style="color:#64748b">{cnt}</span>
  </div>
  <div class="tat-bar" style="width:100%;height:8px">
    <div class="tat-bar-fill" style="width:{pct}%;background:var(--accent)"></div>
  </div>
</div>"""

    # ── Programme Throughput (transitions per programme this month) ──
    this_month = today.strftime("%Y-%m")
    throughput = {}
    for h in history:
        if h["timestamp"][:7] == this_month:
            key = h.get("application_id", "")
            # Get programme from case
            for c in cases:
                if c["application_id"] == key:
                    prog = c["programme_name"]
                    throughput[prog] = throughput.get(prog, 0) + 1
                    break

    tp_html = ""
    if throughput:
        max_tp = max(throughput.values())
        for prog, cnt in sorted(throughput.items(), key=lambda x: -x[1]):
            pct = int(cnt / max_tp * 100)
            tp_html += f"""
<div class="mb-2">
  <div class="d-flex justify-content-between" style="font-size:12px;margin-bottom:3px">
    <span style="font-weight:500">{prog}</span>
    <span style="color:#64748b">{cnt} transitions</span>
  </div>
  <div class="tat-bar" style="width:100%;height:8px">
    <div class="tat-bar-fill" style="width:{pct}%;background:#7c3aed"></div>
  </div>
</div>"""
    else:
        tp_html = '<div style="color:#94a3b8;font-size:13px">No transitions recorded this month.</div>'

    # ── Average TAT per Stage (from stage_history) ──
    stage_durations = {}
    # For each transition in history, look up the previous transition to compute dwell time
    app_timelines = {}
    for h in sorted(history, key=lambda x: x["timestamp"]):
        app = h["application_id"]
        if app not in app_timelines:
            app_timelines[app] = []
        app_timelines[app].append(h)

    for app, transitions in app_timelines.items():
        for i in range(1, len(transitions)):
            prev = transitions[i-1]
            curr = transitions[i]
            try:
                d1 = datetime.strptime(prev["timestamp"], "%Y-%m-%d %H:%M:%S").date()
                d2 = datetime.strptime(curr["timestamp"], "%Y-%m-%d %H:%M:%S").date()
                days = working_days_elapsed(d1.isoformat(), d2)
                stage = prev["to_stage"]
                if stage not in stage_durations:
                    stage_durations[stage] = []
                stage_durations[stage].append(days)
            except Exception:
                pass

    avg_tat_rows = ""
    if stage_durations:
        for stage, durations in sorted(stage_durations.items(), key=lambda x: -sum(x[1])/len(x[1])):
            avg = sum(durations) / len(durations)
            avg_tat_rows += f"""<tr>
  <td style="font-weight:500">{stage}</td>
  <td style="text-align:center">{len(durations)}</td>
  <td style="text-align:center;font-weight:600;color:var(--accent)">{avg:.1f}d</td>
  <td style="text-align:center;color:#94a3b8">{min(durations)}d</td>
  <td style="text-align:center;color:#dc2626">{max(durations)}d</td>
</tr>"""
    else:
        avg_tat_rows = '<tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:20px">Not enough history yet. TAT averages will populate as cases move through stages.</td></tr>'

    content = f"""
<div class="row g-4 mb-4">
  <div class="col-lg-6">
    <div class="card h-100">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-exclamation-triangle-fill" style="color:#dc2626"></i> TAT Breach Report</span>
        <span class="pill pill-danger">{len(breached)} cases</span>
      </div>
      <div style="overflow-x:auto;max-height:360px">
        <table class="data-table">
          <thead><tr><th>App ID</th><th>Org</th><th>Programme</th><th>Stage</th>
            <th style="text-align:center">TAT</th><th style="text-align:center">Elapsed</th>
            <th style="text-align:center">Breach</th><th>Since</th></tr></thead>
          <tbody>{breach_rows if breach_rows else '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:30px">No TAT breaches</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="col-lg-6">
    <div class="card h-100">
      <div class="card-header"><i class="bi bi-funnel-fill" style="color:var(--accent)"></i> Stage Pipeline (Where Cases Are Now)</div>
      <div class="card-body" style="max-height:360px;overflow-y:auto">
        {funnel_html if funnel_html else '<div style="color:#94a3b8;font-size:13px">No cases.</div>'}
      </div>
    </div>
  </div>
</div>

<div class="row g-4">
  <div class="col-lg-5">
    <div class="card">
      <div class="card-header"><i class="bi bi-bar-chart-steps" style="color:#7c3aed"></i> Programme Throughput — {this_month}</div>
      <div class="card-body">
        {tp_html}
      </div>
    </div>
  </div>
  <div class="col-lg-7">
    <div class="card">
      <div class="card-header"><i class="bi bi-clock-history" style="color:#d97706"></i> Average Working Days per Stage</div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>Stage</th><th style="text-align:center">Cases</th>
            <th style="text-align:center">Avg Days</th>
            <th style="text-align:center">Min</th><th style="text-align:center">Max</th></tr></thead>
          <tbody>{avg_tat_rows}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>"""
    return render_page(content, active_page="reports", page_title="Analytics & Reports")


# ── Multi-sheet Excel Export ──────────────────────────────────────────────────
@app.route("/export-excel")
@login_required
def export_excel():
    if not HAS_XLSX:
        flash("openpyxl not installed.", "error")
        return redirect(url_for("dashboard"))
    conn = get_db()
    bid = user_board_id()
    today = date.today()

    if bid is not None:
        cases = [dict(r) for r in conn.execute(
            "SELECT * FROM case_tracking WHERE board_id=?", (bid,)
        ).fetchall()]
        history = [dict(r) for r in conn.execute(
            "SELECT * FROM stage_history WHERE board_id=? ORDER BY timestamp DESC LIMIT 2000", (bid,)
        ).fetchall()]
        audit = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log WHERE board_id=? ORDER BY id DESC LIMIT 2000", (bid,)
        ).fetchall()]
    else:
        cases = [dict(r) for r in conn.execute("SELECT * FROM case_tracking").fetchall()]
        history = [dict(r) for r in conn.execute(
            "SELECT * FROM stage_history ORDER BY timestamp DESC LIMIT 2000"
        ).fetchall()]
        audit = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT 2000"
        ).fetchall()]
    conn.close()

    for c in cases:
        c["days_elapsed"] = working_days_elapsed(c["stage_start_date"], today)
        tat = c["tat_days"]
        elapsed = c["days_elapsed"]
        if c["is_milestone"]:
            c["status"] = "Milestone"
        elif tat > 0 and elapsed >= tat:
            c["status"] = "Overdue"
        elif tat > 0 and elapsed >= c.get("reminder2_day", 0):
            c["status"] = "At Risk"
        else:
            c["status"] = "On Track"

    wb = openpyxl.Workbook()

    # ── Sheet 1: Active Cases ──
    ws1 = wb.active
    ws1.title = "Active Cases"
    hdr_fill = PatternFill("solid", fgColor="003356")
    hdr_font = Font(bold=True, color="FFFFFF")
    headers1 = ["Application ID", "Organisation", "Programme", "Stage", "Status",
                "Days Elapsed", "TAT Days", "Start Date", "Owner Type",
                "Action Owner", "Action Email", "PO Email",
                "R1 Sent", "R2 Sent", "Overdue Sent", "Follow-ups",
                "CC Emails", "Suppress Until"]
    for ci, h in enumerate(headers1, 1):
        cell = ws1.cell(row=1, column=ci, value=h)
        cell.fill = hdr_fill
        cell.font = hdr_font
    for ri, c in enumerate(cases, 2):
        ws1.cell(ri, 1, c["application_id"])
        ws1.cell(ri, 2, c["organisation_name"])
        ws1.cell(ri, 3, c["programme_name"])
        ws1.cell(ri, 4, c["current_stage"])
        ws1.cell(ri, 5, c["status"])
        ws1.cell(ri, 6, c["days_elapsed"])
        ws1.cell(ri, 7, c["tat_days"])
        ws1.cell(ri, 8, c["stage_start_date"])
        ws1.cell(ri, 9, c.get("owner_type") or "")
        ws1.cell(ri, 10, c.get("action_owner_name") or "")
        ws1.cell(ri, 11, c.get("action_owner_email") or "")
        ws1.cell(ri, 12, c.get("program_officer_email") or "")
        ws1.cell(ri, 13, "Yes" if c.get("r1_sent") else "No")
        ws1.cell(ri, 14, "Yes" if c.get("r2_sent") else "No")
        ws1.cell(ri, 15, "Yes" if c.get("overdue_sent") else "No")
        ws1.cell(ri, 16, c.get("overdue_count") or 0)
        ws1.cell(ri, 17, c.get("cc_emails") or "")
        ws1.cell(ri, 18, c.get("suppress_until") or "")
        # Colour overdue rows
        if c["status"] == "Overdue":
            red_fill = PatternFill("solid", fgColor="FEE2E2")
            for ci2 in range(1, len(headers1)+1):
                ws1.cell(ri, ci2).fill = red_fill

    # ── Sheet 2: Stage Transition History ──
    ws2 = wb.create_sheet("Stage History")
    for ci, h in enumerate(["Timestamp", "Application ID", "From Stage", "To Stage", "Changed By"], 1):
        cell = ws2.cell(1, ci, h)
        cell.fill = hdr_fill
        cell.font = hdr_font
    for ri, h in enumerate(history, 2):
        ws2.cell(ri, 1, h["timestamp"])
        ws2.cell(ri, 2, h["application_id"])
        ws2.cell(ri, 3, h.get("from_stage") or "")
        ws2.cell(ri, 4, h["to_stage"])
        ws2.cell(ri, 5, h.get("changed_by") or "")

    # ── Sheet 3: Audit Log ──
    ws3 = wb.create_sheet("Audit Log")
    for ci, h in enumerate(["Timestamp", "Event", "Application ID", "Detail", "User"], 1):
        cell = ws3.cell(1, ci, h)
        cell.fill = hdr_fill
        cell.font = hdr_font
    for ri, a in enumerate(audit, 2):
        ws3.cell(ri, 1, a["timestamp"])
        ws3.cell(ri, 2, a["event_type"])
        ws3.cell(ri, 3, a.get("application_id") or "")
        ws3.cell(ri, 4, a.get("detail") or "")
        ws3.cell(ri, 5, a.get("user_name") or "")

    # ── Sheet 4: TAT Summary ──
    ws4 = wb.create_sheet("TAT Summary")
    for ci, h in enumerate(["Programme", "Total Cases", "Overdue", "At Risk", "On Track", "SLA %"], 1):
        cell = ws4.cell(1, ci, h)
        cell.fill = hdr_fill
        cell.font = hdr_font
    prog_summary = {}
    for c in cases:
        pn = c["programme_name"]
        if pn not in prog_summary:
            prog_summary[pn] = {"total": 0, "overdue": 0, "at_risk": 0, "on_track": 0}
        prog_summary[pn]["total"] += 1
        s = c["status"]
        if s == "Overdue": prog_summary[pn]["overdue"] += 1
        elif s == "At Risk": prog_summary[pn]["at_risk"] += 1
        elif s == "On Track": prog_summary[pn]["on_track"] += 1
    for ri, (pn, d) in enumerate(prog_summary.items(), 2):
        sla = int((d["on_track"] + d["at_risk"]) / d["total"] * 100) if d["total"] else 100
        ws4.cell(ri, 1, pn); ws4.cell(ri, 2, d["total"])
        ws4.cell(ri, 3, d["overdue"]); ws4.cell(ri, 4, d["at_risk"])
        ws4.cell(ri, 5, d["on_track"]); ws4.cell(ri, 6, f"{sla}%")

    # Auto-width
    for ws in [ws1, ws2, ws3, ws4]:
        for col in ws.columns:
            max_w = max((len(str(cell.value or "")) for cell in col), default=10)
            ws.column_dimensions[col[0].column_letter].width = min(max_w + 4, 40)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    fname = f"qci_export_{today.strftime('%Y%m%d')}.xlsx"
    return Response(buf.read(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment;filename={fname}"})


# ── Email Queue Monitor ───────────────────────────────────────────────────────
@app.route("/email-queue")
@board_admin_required
def email_queue_page():
    conn = get_db()
    bid = user_board_id()
    if bid is not None:
        items = [dict(r) for r in conn.execute(
            "SELECT * FROM email_queue WHERE board_id=? OR board_id IS NULL ORDER BY id DESC LIMIT 200",
            (bid,)
        ).fetchall()]
    else:
        items = [dict(r) for r in conn.execute(
            "SELECT * FROM email_queue ORDER BY id DESC LIMIT 200"
        ).fetchall()]
    conn.close()

    STATUS_COLORS = {"sent": "#00984C", "failed": "#dc2626", "pending": "#d97706"}
    rows = ""
    for item in items:
        clr = STATUS_COLORS.get(item["status"], "#64748b")
        rows += f"""<tr>
  <td style="font-size:11px;color:#64748b">{item['queued_at']}</td>
  <td><span class="pill" style="background:{clr}22;color:{clr}">{item['status']}</span></td>
  <td style="font-size:12px">{item.get('application_id') or '—'}</td>
  <td style="font-size:12px">{item.get('notification_type', '')}</td>
  <td style="font-size:12px">{item.get('to_email', '')}</td>
  <td style="font-size:11px;color:#64748b">{item.get('subject', '')[:60]}</td>
  <td style="text-align:center">{item.get('attempts', 0)}</td>
  <td style="font-size:11px;color:#dc2626">{item.get('error_msg', '') or ''}</td>
</tr>"""

    content = f"""
<div class="card">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span><i class="bi bi-send-check" style="color:var(--accent)"></i> Email Queue</span>
    <form method="post" action="/retry-queue">
      <button class="btn btn-sm btn-outline-primary" type="submit">
        <i class="bi bi-arrow-repeat"></i> Retry Failed
      </button>
    </form>
  </div>
  <div style="overflow-x:auto">
    <table class="data-table">
      <thead><tr><th>Queued At</th><th>Status</th><th>App ID</th><th>Type</th>
        <th>To</th><th>Subject</th><th style="text-align:center">Attempts</th><th>Error</th></tr></thead>
      <tbody>{rows if rows else '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:40px">Queue is empty.</td></tr>'}</tbody>
    </table>
  </div>
</div>"""
    return render_page(content, active_page="queue", page_title="Email Queue")


@app.route("/retry-queue", methods=["POST"])
@board_admin_required
def retry_queue():
    """Reset failed emails to pending so next scheduler run retries them."""
    conn = get_db()
    conn.execute("UPDATE email_queue SET status='pending', attempts=0 WHERE status='failed'")
    conn.commit()
    conn.close()
    flash("Failed emails reset to pending. They will be retried on next scheduler run.", "success")
    return redirect(url_for("email_queue_page"))


# ── System Settings (super_admin) ────────────────────────────────────────────
@app.route("/system-settings", methods=["GET", "POST"])
@admin_required
def system_settings():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save_scheduler":
            hour = int(request.form.get("sched_hour", 8))
            minute = int(request.form.get("sched_minute", 0))
            set_app_setting("sched_hour", str(hour))
            set_app_setting("sched_minute", str(minute))
            # Reschedule
            try:
                scheduler.reschedule_job("daily_check", trigger="cron",
                                         hour=hour, minute=minute)
                flash(f"Scheduler updated to {hour:02d}:{minute:02d} IST. Effective immediately.", "success")
            except Exception as e:
                flash(f"Error rescheduling: {e}", "error")

        elif action == "save_webhook":
            set_app_setting("webhook_url", request.form.get("webhook_url", "").strip())
            flash("Webhook URL saved.", "success")

        elif action == "save_2fa":
            uid = request.form.get("user_id")
            enable = request.form.get("enable_2fa")
            conn = get_db()
            if enable:
                secret = totp_generate_secret()
                conn.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, uid))
                conn.commit()
                user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                conn.close()
                uri = totp_provisioning_uri(secret, user["username"])
                import urllib.parse
                qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=180x180&data={urllib.parse.quote(uri)}"
                flash(f"2FA enabled for {user['username']}. Secret: {secret}", "success")
            else:
                conn.execute("UPDATE users SET totp_secret=NULL WHERE id=?", (uid,))
                conn.commit()
                conn.close()
                flash("2FA disabled.", "success")

        elif action == "force_reset":
            uid = request.form.get("user_id")
            conn = get_db()
            conn.execute("UPDATE users SET force_password_reset=1 WHERE id=?", (uid,))
            conn.commit()
            conn.close()
            flash("User will be required to reset password on next login.", "success")

    sched_hour   = int(get_app_setting("sched_hour", "8"))
    sched_minute = int(get_app_setting("sched_minute", "0"))
    webhook_url  = get_app_setting("webhook_url", "")

    conn = get_db()
    users = [dict(r) for r in conn.execute("SELECT id, username, totp_secret, force_password_reset FROM users ORDER BY username").fetchall()]
    conn.close()

    user_rows = ""
    for u in users:
        has_2fa = bool(u["totp_secret"])
        needs_reset = bool(u["force_password_reset"])
        user_rows += f"""<tr>
  <td style="font-weight:600">{u['username']}</td>
  <td><span class="pill {'pill-ok' if has_2fa else 'pill-muted'}">{('Enabled' if has_2fa else 'Off')}</span></td>
  <td>{'<span class="pill pill-warn">Required</span>' if needs_reset else '<span style="color:#94a3b8;font-size:12px">—</span>'}</td>
  <td style="white-space:nowrap">
    <form method="post" class="d-inline">
      <input type="hidden" name="user_id" value="{u['id']}">
      <input type="hidden" name="action" value="save_2fa">
      <input type="hidden" name="enable_2fa" value="{'0' if has_2fa else '1'}">
      <button class="btn btn-sm btn-action {'btn-outline-danger' if has_2fa else 'btn-outline-success'}" type="submit">
        {'Disable 2FA' if has_2fa else 'Enable 2FA'}</button>
    </form>
    <form method="post" class="d-inline ms-1">
      <input type="hidden" name="user_id" value="{u['id']}">
      <input type="hidden" name="action" value="force_reset">
      <button class="btn btn-sm btn-action btn-outline-warning" type="submit">Force PW Reset</button>
    </form>
  </td>
</tr>"""

    minute_opts = "".join(
        f'<option value="{m:02d}" {"selected" if m == sched_minute else ""}>{m:02d}</option>'
        for m in [0, 15, 30, 45]
    )
    hour_opts = "".join(
        f'<option value="{h}" {"selected" if h == sched_hour else ""}>{h:02d}:00</option>'
        for h in range(24)
    )

    content = f"""
<div class="row g-4">
  <div class="col-lg-5">
    <div class="card mb-4">
      <div class="card-header"><i class="bi bi-alarm" style="color:var(--accent)"></i> Scheduler Time (IST)</div>
      <div class="card-body p-4">
        <form method="post">
          <input type="hidden" name="action" value="save_scheduler">
          <div class="row g-2 mb-3">
            <div class="col-6">
              <label class="form-label" style="font-size:12px">Hour (24h)</label>
              <select class="form-select" name="sched_hour">{hour_opts}</select>
            </div>
            <div class="col-6">
              <label class="form-label" style="font-size:12px">Minute</label>
              <select class="form-select" name="sched_minute">{minute_opts}</select>
            </div>
          </div>
          <button class="btn btn-primary w-100" type="submit">Update Schedule</button>
        </form>
        <div style="font-size:11px;color:#94a3b8;margin-top:8px">
          Currently: <strong>{sched_hour:02d}:{sched_minute:02d} IST</strong>. Applies to all programmes.
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><i class="bi bi-send-arrow-up" style="color:#7c3aed"></i> Outbound Webhook</div>
      <div class="card-body p-4">
        <form method="post">
          <input type="hidden" name="action" value="save_webhook">
          <div class="mb-3">
            <label class="form-label" style="font-size:12px">Webhook URL</label>
            <input type="url" class="form-control" name="webhook_url"
                   value="{webhook_url}" placeholder="https://your-gateway/hook">
          </div>
          <button class="btn btn-primary w-100" type="submit">Save Webhook</button>
        </form>
        <div style="font-size:11px;color:#94a3b8;margin-top:8px">
          POST fired on every notification. JSON: <code style="font-size:10px">{{"event":"notification_r1","data":{{...}}}}</code><br>
          Use with MSG91, Gupshup, Twilio, etc. Leave blank to disable.
        </div>
      </div>
    </div>
  </div>

  <div class="col-lg-7">
    <div class="card">
      <div class="card-header"><i class="bi bi-shield-lock-fill" style="color:#7c3aed"></i> User Security</div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>Username</th><th>2FA</th><th>PW Reset</th><th>Actions</th></tr></thead>
          <tbody>{user_rows}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>"""
    return render_page(content, active_page="system", page_title="System Settings")


# ── Database Backup ───────────────────────────────────────────────────────────
@app.route("/backup")
@admin_required
def backup_db():
    flash(
        "Database backup is not available in PostgreSQL mode. "
        "Use pg_dump via your Railway database dashboard or CLI to export data.",
        "info",
    )
    return redirect(url_for("system_settings"))


@app.route("/export-dashboard")
@login_required
def export_dashboard():
    """Export current dashboard data as CSV download."""
    conn = get_db()
    bid = user_board_id()
    q = "SELECT * FROM case_tracking"
    params = []
    if bid is not None:
        q += " WHERE board_id=?"
        params.append(bid)
    cases = [dict(r) for r in conn.execute(q, params).fetchall()]
    conn.close()
    today = date.today()

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow([
        "Application ID", "Organisation", "Programme", "Stage", "Owner Type",
        "Action Owner", "Email", "Stage Start", "TAT Days", "Days Elapsed",
        "Status", "R1 Sent", "R2 Sent", "Overdue Sent", "Follow-ups"
    ])
    for c in cases:
        elapsed = working_days_elapsed(c["stage_start_date"], today)
        if c["is_milestone"]:
            status = "Milestone"
        elif c["tat_days"] > 0 and elapsed >= c["tat_days"]:
            status = "Overdue"
        elif c["tat_days"] > 0 and elapsed >= c["reminder2_day"]:
            status = "At Risk"
        else:
            status = "On Track"
        w.writerow([
            c["application_id"], c["organisation_name"], c["programme_name"],
            c["current_stage"], c["owner_type"] or "",
            c["action_owner_name"] or "", c["action_owner_email"] or "",
            c["stage_start_date"], c["tat_days"], elapsed,
            status, "Yes" if c["r1_sent"] else "No",
            "Yes" if c["r2_sent"] else "No",
            "Yes" if c["overdue_sent"] else "No", c["overdue_count"]
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=qci_dashboard_{today}.csv"}
    )


@app.route("/run-check")
@admin_required
def run_check():
    def _bg():
        try:
            run_daily_check()
        except Exception as exc:
            log.error("Background run-check failed: %s", exc)

    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"status": "started", "message": "Daily check is running in the background."})


# ── Scheduler ─────────────────────────────────────────────────────────────────
def _scheduled_job():
    """Run the daily check with an atomic DB-level lock so only one worker fires it."""
    worker_id = secrets.token_hex(8)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Stale lock threshold: if another worker crashed, release locks older than 10 min
    stale_cutoff = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        # Delete any stale locks first
        conn.execute(
            "DELETE FROM scheduler_locks WHERE lock_name='daily_check' AND locked_at < ?",
            (stale_cutoff,),
        )
        conn.commit()
        # Atomically claim the lock — fails silently if another worker already holds it
        conn.execute(
            "INSERT INTO scheduler_locks (lock_name, locked_at, worker_id) VALUES (?,?,?) "
            "ON CONFLICT (lock_name) DO NOTHING",
            ("daily_check", now_str, worker_id),
        )
        conn.commit()
        # Check whether we won the lock
        row = conn.execute(
            "SELECT worker_id FROM scheduler_locks WHERE lock_name='daily_check'",
        ).fetchone()
        if not row or row["worker_id"] != worker_id:
            log.info("Scheduler lock held by another worker — skipping.")
            return
    finally:
        conn.close()

    try:
        log.info("Scheduled daily check running… (worker %s)", worker_id)
        result = run_daily_check()
        log.info("Daily check complete: %s", result)
    finally:
        # Release the lock
        rel = get_db()
        try:
            rel.execute(
                "DELETE FROM scheduler_locks WHERE lock_name='daily_check' AND worker_id=?",
                (worker_id,),
            )
            rel.commit()
        finally:
            rel.close()


scheduler = BackgroundScheduler(timezone="Asia/Kolkata")

# ── App startup ───────────────────────────────────────────────────────────────
with app.app_context():
    init_db()
    migrate_data()
    seed_data()
    # Read schedule from DB (default: 08:00 IST)
    _sched_hour   = int(get_app_setting("scheduler_hour",   "8"))
    _sched_minute = int(get_app_setting("scheduler_minute", "0"))

scheduler.add_job(_scheduled_job, "cron",
                  hour=_sched_hour, minute=_sched_minute, id="daily_check")

scheduler.start()

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, port=5050)
