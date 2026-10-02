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
    return app.test_client()


# ---------- auth primitives ----------


def test_password_hash_roundtrip():
    stored = hash_password("correct-horse")
    assert verify_password("correct-horse", stored)
    assert not verify_password("wrong", stored)


def test_password_hash_is_salted():
    assert hash_password("same") != hash_password("same")


def test_password_verify_rejects_malformed_hash():
    assert not verify_password("x", "no-salting-here")


def test_token_roundtrip():
    tok = issue_token("alice")
    assert validate_token(tok) == "alice"


def test_token_rejects_tampered_signature():
    tok = issue_token("alice")
    user, exp, _ = tok.split(".")
    assert validate_token(f"{user}.{exp}.deadbeef") is None


def test_token_rejects_malformed():
    assert validate_token("garbage") is None
    assert validate_token("a.b") is None


def test_token_rejects_expired(monkeypatch):
    import mano.auth as authmod

    tok = authmod.issue_token("alice")
    real_time = authmod.time.time
    monkeypatch.setattr(authmod.time, "time", lambda: real_time() + authmod.TOKEN_TTL_SECONDS + 10)
    assert authmod.validate_token(tok) is None


# ---------- registration ----------


def test_register_ok(client):
    r = client.post("/api/register", json={"username": "bob", "password": "longenough"})
    assert r.status_code == 201


def test_register_rejects_short_password(client):
    r = client.post("/api/register", json={"username": "bob", "password": "short"})
    assert r.status_code == 400


def test_register_rejects_bad_username(client):
    r = client.post("/api/register", json={"username": "B!", "password": "longenough"})
    assert r.status_code == 400


def test_register_duplicate_conflicts(client):
    r = client.post("/api/register", json={"username": "alice", "password": "longenough"})
    assert r.status_code == 409


def test_register_missing_fields(client):
    assert client.post("/api/register", json={}).status_code == 400


# ---------- login ----------


def test_login_ok(client):
    r = client.post("/api/login", json={"username": "alice", "password": "correct-horse"})
    assert r.status_code == 200 and "token" in r.get_json()


def test_login_wrong_password(client):
    r = client.post("/api/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401


def test_login_unknown_user(client):
    r = client.post("/api/login", json={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401


def test_login_missing_fields(client):
    assert client.post("/api/login", json={"username": "alice"}).status_code == 400


# ---------- protected routes ----------


def _auth(client, username="alice"):
    tok = client.post(
        "/api/login", json={"username": username, "password": "correct-horse"}
    ).get_json()["token"]
    return {"Authorization": f"Bearer {tok}"}


def test_list_users_requires_auth(client):
    assert client.get("/api/users").status_code == 401


def test_list_users_rejects_bad_scheme(client):
    assert client.get("/api/users", headers={"Authorization": "Basic x"}).status_code == 401


def test_list_users_ok(client):
    r = client.get("/api/users", headers=_auth(client))
    assert r.status_code == 200 and r.get_json()[0]["username"] == "alice"


def test_list_users_never_leaks_hashes(client):
    r = client.get("/api/users", headers=_auth(client))
    assert "password_hash" not in r.get_json()[0]


def test_get_user_ok(client):
    r = client.get("/api/users/alice", headers=_auth(client))
    assert r.status_code == 200


def test_get_user_404(client):
    r = client.get("/api/users/ghost", headers=_auth(client))
    assert r.status_code == 404


def test_get_user_rejects_garbage_token(client):
    r = client.get("/api/users/alice", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_delete_own_user(client):
    assert client.delete("/api/users/alice", headers=_auth(client)).status_code == 200


def test_delete_other_user_forbidden(client):
    client.post("/api/register", json={"username": "bob", "password": "longenough"})
    bob = client.post("/api/login", json={"username": "bob", "password": "longenough"}).get_json()
    r = client.delete(
        "/api/users/alice", headers={"Authorization": f"Bearer {bob['token']}"}
    )
    assert r.status_code == 403


def test_404_handler_shape(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and "error" in r.get_json()