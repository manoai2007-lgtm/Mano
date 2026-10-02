<<<<<<< HEAD
# Mano
=======
# Mano

A small user-management API in Flask: registration, login, and authenticated
user CRUD backed by SQLite.

Built to be reviewed — it is not production-hardened.

## Layout

```
mano/
  app.py      application factory, error handlers
  routes.py   HTTP endpoints and the auth decorator
  auth.py     PBKDF2 password hashing, HMAC tokens
  db.py       SQLite connection and schema
tests/
  test_mano.py
```

## Run

```bash
pip install -r requirements.txt
python -m mano.app          # http://127.0.0.1:8000
```

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/register` | no | create a user |
| POST | `/api/login` | no | get a bearer token |
| GET | `/api/users` | yes | list users |
| GET | `/api/users/<username>` | yes | fetch one user |
| DELETE | `/api/users/<username>` | yes | delete yourself |

## Auth

Passwords are hashed with PBKDF2-SHA256 (100k iterations, per-user salt).
Tokens are HMAC-SHA256 signed and expire after one hour. The signing secret comes
from `MANO_SECRET` — set it in production.

```bash
curl -X POST localhost:8000/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"longenough"}'

curl -X POST localhost:8000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"longenough"}'
```

## Quality gates

```bash
pytest -q            # 26 tests
ruff check .
mypy mano/ --strict
```

CI runs all three on every push and pull request.

## Known gaps

- No rate limiting on `/login` — brute-forceable.
- No CSRF protection; the API is bearer-token only so it is not directly exposed
  to browser sessions.
- `MANO_SECRET` falls back to a hardcoded default if unset.
>>>>>>> 1f2cec9 (Mano API: Flask user service with auth, tests, and CI gates)
