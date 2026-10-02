"""HTTP routes for the user API."""
import re
import sqlite3
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import Blueprint, Response, g, jsonify, request

from .auth import hash_password, issue_token, validate_token, verify_password
from .db import get_db

api = Blueprint("api", __name__)

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")


def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Reject the request unless it carries a valid bearer token."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="unauthorized"), 401
        username = validate_token(header[7:])
        if username is None:
            return jsonify(error="invalid token"), 401
        g.current_user = username
        return fn(*args, **kwargs)

    return wrapper


@api.post("/login")
def login() -> tuple[Response, int] | Response:
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify(error="username and password required"), 400

    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify(error="invalid credentials"), 401

    return jsonify(token=issue_token(username))


@api.post("/register")
def register() -> tuple[Response, int] | Response:
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not USERNAME_RE.match(username or ""):
        return jsonify(error="username must be 3-32 chars, lowercase/digits/underscore"), 400
    if not password or len(password) < 8:
        return jsonify(error="password must be at least 8 characters"), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username already taken"), 409

    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify(id=new_id), 201


@api.get("/users")
@require_auth
def list_users() -> Response:
    rows = get_db().execute("SELECT id, username, created_at FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@api.get("/users/<username>")
@require_auth
def get_user(username: str) -> tuple[Response, int] | Response:
    row = get_db().execute(
        "SELECT id, username, created_at FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return jsonify(error="no such user"), 404
    return jsonify(dict(row))


@api.delete("/users/<username>")
@require_auth
def delete_user(username: str) -> tuple[Response, int] | Response:
    if username != g.get("current_user"):
        return jsonify(error="cannot delete another user"), 403
    db = get_db()
    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.commit()
    return jsonify(deleted=username)