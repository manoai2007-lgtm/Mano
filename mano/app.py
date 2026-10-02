"""Mano — a small user-management API.

Deliberately minimal: routes, validation, auth, and a SQLite layer. Built to be
reviewed, not to be production-ready.
"""
import os
from typing import Any

from flask import Flask, Response, g, jsonify

from .db import init_db
from .routes import api


def create_app(database: str | None = None, testing: bool = False) -> Flask:
    """Application factory — each call yields an isolated app instance."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("MANO_SECRET", "dev-secret-change-me")
    app.config["DATABASE"] = database or os.environ.get("MANO_DB", "mano.db")
    app.config["TESTING"] = testing

    app.register_blueprint(api, url_prefix="/api")

    @app.teardown_appcontext
    def close_db(_exc: object = None) -> None:
        db: Any = g.pop("db", None)
        if db is not None:
            db.close()

    @app.errorhandler(404)
    def not_found(_e: object) -> tuple[Response, int]:
        return jsonify(error="not found"), 404

    with app.app_context():
        init_db(app)
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=8000, debug=True)