import logging
import os

import redis as redis_lib
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
redis_client: redis_lib.Redis | None = None

_log = logging.getLogger(__name__)


def init_extensions(app: Flask) -> None:
    db.init_app(app)

    global redis_client
    _redis_timeout = float(os.getenv("NIS2_REDIS_TIMEOUT", "5"))
    try:
        client = redis_lib.from_url(
            app.config["REDIS_URL"],
            decode_responses=True,
            socket_connect_timeout=_redis_timeout,
            socket_timeout=_redis_timeout,
        )
        client.ping()  # validate connectivity at startup
        redis_client = client
    except Exception as exc:
        _log.warning(
            "Redis unavailable at startup (%s) — rate limiting and caching disabled",
            exc,
        )
        redis_client = None
