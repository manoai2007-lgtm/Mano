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
        """Validate the bearer token, set the current user, and call the route."""
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="unauthorized"), 401
        username = validate_token(header[7:])
        if username is None:
            return jsonify(error="invalid token"), 401
        g.current_user = username
        return fn(*args, **kwargs)

    return wrapper


@api.route("/login", methods=["POST"])
def login() -> tuple[Response, int] | Response:
    """Return a bearer token, or a 400/401 error for missing/invalid credentials."""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    # The payload is untrusted: a JSON number or list passes a truthiness check
    # but explodes downstream with an AttributeError.
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password must be strings"), 400
    if not username or not password:
        return jsonify(error="username and password required"), 400

    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify(error="invalid credentials"), 401

    resp: Response = jsonify(token=issue_token(username))
    return resp


@api.route("/register", methods=["POST"])
def register() -> tuple[Response, int] | Response:
    """Create a user and return its ID, or a 400/409 validation/conflict error."""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password must be strings"), 400
    if not USERNAME_RE.match(username):
        return jsonify(error="username must be 3-32 chars, lowercase/digits/underscore"), 400
    if len(password) < 8:
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


@api.route("/users", methods=["GET"])
@require_auth
def list_users() -> Response:
    """Return all users with their IDs and creation times, excluding hashes."""
    rows = get_db().execute("SELECT id, username, created_at FROM users").fetchall()
    resp: Response = jsonify([dict(r) for r in rows])
    return resp


@api.route("/users/<username>", methods=["GET"])
@require_auth
def get_user(username: str) -> tuple[Response, int] | Response:
    """Return public details for the named user, or HTTP 404 if absent."""
    row = get_db().execute(
        "SELECT id, username, created_at FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return jsonify(error="no such user"), 404
    resp: Response = jsonify(dict(row))
    return resp


@api.route("/users/<username>", methods=["DELETE"])
@require_auth
def delete_user(username: str) -> tuple[Response, int] | Response:
    """Delete the named user if it matches the token identity; otherwise return 403."""
    if username != g.get("current_user"):
        return jsonify(error="cannot delete another user"), 403
    db = get_db()
    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.commit()
    resp: Response = jsonify(deleted=username)
    return resp
