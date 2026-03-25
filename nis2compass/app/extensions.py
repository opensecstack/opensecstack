import logging

from flask_sqlalchemy import SQLAlchemy
import redis as redis_lib

db = SQLAlchemy()
redis_client: redis_lib.Redis | None = None

_log = logging.getLogger(__name__)


def init_extensions(app) -> None:
    db.init_app(app)

    global redis_client
    try:
        client = redis_lib.from_url(
            app.config['REDIS_URL'],
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        client.ping()  # validate connectivity at startup
        redis_client = client
    except Exception as exc:
        _log.warning(
            'Redis unavailable at startup (%s) — rate limiting and caching disabled',
            exc,
        )
        redis_client = None
