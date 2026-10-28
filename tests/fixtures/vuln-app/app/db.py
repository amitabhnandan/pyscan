"""Credential lookup for the demo app."""
import sqlite3

DB_PATH = "users.db"


def _connect():
    return sqlite3.connect(DB_PATH)


def check_login(user, password):
    conn = _connect()
    cur = conn.cursor()
    # line 15: SQL built by string formatting -> injection
    cur.execute(f"SELECT 1 FROM users WHERE u='{user}' AND p='{password}'")
    return cur.fetchone() is not None
