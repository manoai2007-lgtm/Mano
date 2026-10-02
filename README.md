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
export MANO_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m mano.app          # http://127.0.0.1:8000
```

The app exits with an error if `MANO_SECRET` is unset.

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
Tokens are HMAC-SHA256 signed and expire after one hour. The signing secret is read
from `MANO_SECRET` and the app refuses to start without it — there is no fallback,
because a hardcoded default would let anyone forge a token for any user.

```bash
export MANO_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

`MANO_DEBUG=1` enables the Werkzeug debugger; it is off by default.

```bash
curl -X POST localhost:8000/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"longenough"}'

curl -X POST localhost:8000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"longenough"}'
```

## Quality gates

Install the tooling first — `requirements.txt` covers runtime only:

```bash
pip install -r requirements.txt
pip install mypy ruff types-flask bandit pip-audit
```

Then:

```bash
pytest -q            # 32 tests
ruff check .
mypy mano/ --strict
bandit -r mano/      # Python security linter
pip-audit -r requirements.txt
```

CI runs all five on every push and pull request. `bandit` and `pip-audit` are the
static-security half of the gate — they catch hardcoded secrets, weak crypto, and
known CVEs in dependencies without needing a running deployment.

## Known gaps

- No rate limiting or lockout on repeated failed logins.
- No CSRF protection; the API is bearer-token only so it is not directly exposed
  to browser sessions.
