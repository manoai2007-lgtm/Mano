"""SQLite access layer. One connection per request, keyed off the app context."""
import sqlite3

from flask import Flask, current_app, g


def get_db() -> sqlite3.Connection:
    """Return this request's connection, opening one on first use."""
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    conn: sqlite3.Connection = g.db
    return conn


def init_db(app: "Flask | None" = None) -> None:
    """Create the schema if absent. Uses the current app when none is passed."""
    target = app or current_app
    db = sqlite3.connect(target.config["DATABASE"])
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    db.commit()
    db.close()