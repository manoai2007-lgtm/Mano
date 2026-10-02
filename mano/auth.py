"""Token issuing and verification.

Tokens are HMAC-signed and carry an expiry. Signing secrets are read from the
environment so they are not baked into the source tree.
"""
import hashlib
import hmac
import os
import secrets
import time

TOKEN_TTL_SECONDS = 3600
_SECRET = os.environ.get("MANO_SECRET", "insecure-default-secret")


def hash_password(password: str) -> str:
    """PBKDF2-SHA256 with a per-user random salt."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, _, expected = stored.partition("$")
    if not expected:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return hmac.compare_digest(digest.hex(), expected)


def issue_token(username: str) -> str:
    """Return `<username>.<expiry>.<signature>`."""
    expiry = str(int(time.time()) + TOKEN_TTL_SECONDS)
    payload = f"{username}.{expiry}"
    sig = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def validate_token(token: str) -> str | None:
    """Return the username if the token is valid and unexpired, else None."""
    try:
        username, expiry, sig = token.split(".")
    except ValueError:
        return None
    payload = f"{username}.{expiry}"
    expected = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    if int(expiry) < int(time.time()):
        return None
    return username