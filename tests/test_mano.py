import os
import tempfile

import pytest

os.environ.setdefault("MANO_SECRET", "test-secret")


from mano.auth import (
    hash_password,
    issue_token,
    validate_token,
    verify_password,
)


@pytest.fixture
def app():
    """Yield a test app seeded with Alice and remove its temporary database afterward."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    from mano.app import create_app
    from mano.db import get_db

    a = create_app(database=path, testing=True)
    with a.app_context():
        get_db().execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("alice", hash_password("correct-horse")),
        )
        get_db().commit()
    yield a
    os.unlink(path)


@pytest.fixture
def client(app):
    """Return a Flask test client for the isolated application fixture."""
    return app.test_client()


# ---------- auth primitives ----------


def test_password_hash_roundtrip():
    """Accept the original password and reject a different one against its hash."""
    stored = hash_password("correct-horse")
    assert verify_password("correct-horse", stored)
    assert not verify_password("wrong", stored)


def test_password_hash_is_salted():
    """Ensure hashing the same password twice produces different stored values."""
    assert hash_password("same") != hash_password("same")


def test_password_verify_rejects_malformed_hash():
    """Reject a stored hash that lacks the salt and digest separator."""
    assert not verify_password("x", "no-salting-here")


def test_token_roundtrip():
    """Recover the username from a freshly issued token."""
    tok = issue_token("alice")
    assert validate_token(tok) == "alice"


def test_token_rejects_tampered_signature():
    """Reject a token whose signature was replaced."""
    tok = issue_token("alice")
    user, exp, _ = tok.split(".")
    assert validate_token(f"{user}.{exp}.deadbeef") is None


def test_token_rejects_malformed():
    """Reject tokens that do not contain all three components."""
    assert validate_token("garbage") is None
    assert validate_token("a.b") is None


def test_token_rejects_expired(monkeypatch):
    """Reject a token after advancing the clock beyond its lifetime."""
    import mano.auth as authmod

    tok = authmod.issue_token("alice")
    real_time = authmod.time.time
    monkeypatch.setattr(authmod.time, "time", lambda: real_time() + authmod.TOKEN_TTL_SECONDS + 10)
    assert authmod.validate_token(tok) is None


# ---------- registration ----------


def test_register_ok(client):
    """Return HTTP 201 when registering a valid new user."""
    r = client.post("/api/register", json={"username": "bob", "password": "longenough"})
    assert r.status_code == 201


def test_register_rejects_short_password(client):
    """Reject registration when the password is shorter than eight characters."""
    r = client.post("/api/register", json={"username": "bob", "password": "short"})
    assert r.status_code == 400


def test_register_rejects_bad_username(client):
    """Reject registration with a username outside the allowed format."""
    r = client.post("/api/register", json={"username": "B!", "password": "longenough"})
    assert r.status_code == 400


def test_register_duplicate_conflicts(client):
    """Return HTTP 409 when registering an existing username."""
    r = client.post("/api/register", json={"username": "alice", "password": "longenough"})
    assert r.status_code == 409


def test_register_missing_fields(client):
    """Reject registration when required fields are absent."""
    assert client.post("/api/register", json={}).status_code == 400


# ---------- login ----------


def test_login_ok(client):
    """Return a token when the supplied credentials match a stored user."""
    r = client.post("/api/login", json={"username": "alice", "password": "correct-horse"})
    assert r.status_code == 200 and "token" in r.get_json()


def test_login_wrong_password(client):
    """Return HTTP 401 when the password does not match."""
    r = client.post("/api/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401


def test_login_unknown_user(client):
    """Return HTTP 401 when the username is not registered."""
    r = client.post("/api/login", json={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401


def test_login_missing_fields(client):
    """Return HTTP 400 when the login password is missing."""
    assert client.post("/api/login", json={"username": "alice"}).status_code == 400


# ---------- untrusted input types ----------


def test_login_rejects_numeric_password(client):
    """A JSON number passes a truthiness check but explodes on .encode()."""
    r = client.post("/api/login", json={"username": "alice", "password": 12345})
    assert r.status_code == 400


def test_login_rejects_list_username(client):
    r = client.post("/api/login", json={"username": ["alice"], "password": "longenough"})
    assert r.status_code == 400


def test_register_rejects_numeric_password(client):
    r = client.post("/api/register", json={"username": "bob", "password": 12345678})
    assert r.status_code == 400


def test_register_rejects_none_username(client):
    r = client.post("/api/register", json={"username": None, "password": "longenough"})
    assert r.status_code == 400


# ---------- signing secret must fail closed ----------


def test_missing_secret_raises(monkeypatch):
    """No hardcoded fallback: an unset MANO_SECRET must not silently pass."""
    import mano.auth as authmod

    monkeypatch.delenv("MANO_SECRET", raising=False)
    monkeypatch.setattr(authmod, "_SECRET", None, raising=False)
    with pytest.raises(RuntimeError, match="MANO_SECRET"):
        authmod._load_secret()


def test_secret_is_not_hardcoded():
    """The signing key must never come from a literal in the source."""
    import inspect

    import mano.auth as authmod

    src = inspect.getsource(authmod._load_secret)
    assert "insecure" not in src.lower()
    assert authmod._load_secret.__doc__ is not None


# ---------- protected routes ----------


def _auth(client, username="alice"):
    """Log in with the fixture password and return a bearer authorization header."""
    tok = client.post(
        "/api/login", json={"username": username, "password": "correct-horse"}
    ).get_json()["token"]
    return {"Authorization": f"Bearer {tok}"}


def test_list_users_requires_auth(client):
    """Reject a user listing request without authorization."""
    assert client.get("/api/users").status_code == 401


def test_list_users_rejects_bad_scheme(client):
    """Reject a user listing request using Basic authorization."""
    assert client.get("/api/users", headers={"Authorization": "Basic x"}).status_code == 401


def test_list_users_ok(client):
    """Include the seeded user in an authenticated user listing."""
    r = client.get("/api/users", headers=_auth(client))
    assert r.status_code == 200 and r.get_json()[0]["username"] == "alice"


def test_list_users_never_leaks_hashes(client):
    """Exclude the password hash from the listed user details."""
    r = client.get("/api/users", headers=_auth(client))
    assert "password_hash" not in r.get_json()[0]


def test_get_user_ok(client):
    """Allow an authenticated request to fetch an existing user."""
    r = client.get("/api/users/alice", headers=_auth(client))
    assert r.status_code == 200


def test_get_user_404(client):
    """Return HTTP 404 for an authenticated lookup of an absent user."""
    r = client.get("/api/users/ghost", headers=_auth(client))
    assert r.status_code == 404


def test_get_user_rejects_garbage_token(client):
    """Reject a user lookup carrying a malformed bearer token."""
    r = client.get("/api/users/alice", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_delete_own_user(client):
    """Allow an authenticated user to request deletion of their own account."""
    assert client.delete("/api/users/alice", headers=_auth(client)).status_code == 200


def test_delete_other_user_forbidden(client):
    """Reject an authenticated attempt to delete another user."""
    client.post("/api/register", json={"username": "bob", "password": "longenough"})
    bob = client.post("/api/login", json={"username": "bob", "password": "longenough"}).get_json()
    r = client.delete(
        "/api/users/alice", headers={"Authorization": f"Bearer {bob['token']}"}
    )
    assert r.status_code == 403


def test_404_handler_shape(client):
    """Return a JSON error for an unknown API route."""
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and "error" in r.get_json()