"""Shared pytest fixtures for QCI Notifications test suite.

Sets up env vars, provides a SQLite-backed mock for get_db(), and
creates Flask test clients with pre-authenticated sessions.
"""
import os
import re
import sqlite3
import pytest
from cryptography.fernet import Fernet

# ── Environment — must be set BEFORE importing app ───────────────────────────
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest-only")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ["VERCEL"] = "1"       # disables APScheduler
os.environ["TESTING"] = "1"      # skips init_db/seed_data at import
os.environ.setdefault("DATABASE_URL", "postgresql://fake:fake@localhost/fake")


# ── SQLite mock that mirrors DBConn's interface ──────────────────────────────
class _DictRow(dict):
    """sqlite3.Row doesn't support dict(), so we wrap results."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class _Cursor:
    """Wraps a sqlite3.Cursor to return _DictRow objects."""
    def __init__(self, cur):
        self._cur = cur
        self._desc = None

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self._cur.description]
        return _DictRow(zip(cols, row))

    def fetchall(self):
        rows = self._cur.fetchall()
        if not rows:
            return []
        cols = [d[0] for d in self._cur.description]
        return [_DictRow(zip(cols, r)) for r in rows]

    @property
    def lastrowid(self):
        return self._cur.lastrowid


_PG_TO_SQLITE = [
    (re.compile(r"SERIAL\s+PRIMARY\s+KEY", re.I), "INTEGER PRIMARY KEY AUTOINCREMENT"),
    (re.compile(r"ON\s+CONFLICT\s*\([^)]+\)\s+DO\s+NOTHING", re.I), ""),
    (re.compile(r"ON\s+CONFLICT\s*\([^)]+\)\s+DO\s+UPDATE\s+SET\s+[^;]+", re.I), ""),
    (re.compile(r"REFERENCES\s+\w+\(\w+\)(\s+ON\s+DELETE\s+CASCADE)?", re.I), ""),
    (re.compile(r"NULLS\s+(FIRST|LAST)", re.I), ""),
    (re.compile(r"ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS", re.I), "ADD COLUMN"),
]


def _pg_to_sqlite_sql(sql):
    """Convert PostgreSQL SQL to SQLite-compatible SQL."""
    # %s → ?
    result = []
    i = 0
    in_q = False
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            in_q = not in_q
        elif ch == '%' and not in_q and i + 1 < len(sql) and sql[i + 1] == 's':
            result.append('?')
            i += 2
            continue
        result.append(ch)
        i += 1
    sql = ''.join(result)
    for pat, repl in _PG_TO_SQLITE:
        sql = pat.sub(repl, sql)
    return sql


class SqliteDBConn:
    """Drop-in replacement for app.DBConn backed by in-memory SQLite."""

    def __init__(self, sqlite_conn):
        self._conn = sqlite_conn

    def execute(self, sql, params=()):
        sql = _pg_to_sqlite_sql(sql)
        try:
            cur = self._conn.execute(sql, params)
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                return _Cursor(self._conn.cursor())
            raise
        return _Cursor(cur)

    def executescript(self, sql):
        sql = _pg_to_sqlite_sql(sql)
        # sqlite3.executescript auto-commits — split and execute instead
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt:
                try:
                    self._conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass  # skip unsupported ALTER TABLE etc.
        self._conn.commit()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        pass  # keep shared connection alive


# ── Shared in-memory SQLite ──────────────────────────────────────────────────
_sqlite_conn = None


def _get_sqlite():
    global _sqlite_conn
    if _sqlite_conn is None:
        _sqlite_conn = sqlite3.connect(":memory:", check_same_thread=False)
    return _sqlite_conn


def _mock_get_db():
    return SqliteDBConn(_get_sqlite())


# ── Session-scoped setup: patch get_db, run init_db + seed_data ──────────────
@pytest.fixture(scope="session", autouse=True)
def _setup_test_db():
    import app as _app
    _app.get_db = _mock_get_db
    with _app.app.app_context():
        _app.init_db()
        try:
            _app.migrate_data()
        except Exception:
            _get_sqlite().rollback()
        try:
            _app.seed_data()
        except Exception:
            _get_sqlite().rollback()
    _get_sqlite().commit()
    yield
    global _sqlite_conn
    if _sqlite_conn:
        _sqlite_conn.close()
        _sqlite_conn = None


@pytest.fixture(scope="session")
def flask_app():
    import app as _app
    _app.app.config["TESTING"] = True
    return _app.app


@pytest.fixture
def client(flask_app):
    with flask_app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Super admin session."""
    with client.session_transaction() as s:
        s["user_id"] = 1
        s["username"] = "admin"
        s["role"] = "super_admin"
        s["full_name"] = "Test Admin"
        s["board_id"] = None
        s["board_name"] = ""
        s["csrf_token"] = "test-csrf"
    yield client


@pytest.fixture
def board_admin_client(client):
    """Board admin session (NABH, board_id=1)."""
    with client.session_transaction() as s:
        s["user_id"] = 3
        s["username"] = "ba_user"
        s["role"] = "board_admin"
        s["full_name"] = "Board Admin"
        s["board_id"] = 1
        s["board_name"] = "NABH"
        s["csrf_token"] = "test-csrf"
    yield client


@pytest.fixture
def officer_client(client):
    """Program officer session (NABH, board_id=1)."""
    with client.session_transaction() as s:
        s["user_id"] = 2
        s["username"] = "officer"
        s["role"] = "program_officer"
        s["full_name"] = "Test Officer"
        s["board_id"] = 1
        s["board_name"] = "NABH"
        s["csrf_token"] = "test-csrf"
    yield client
