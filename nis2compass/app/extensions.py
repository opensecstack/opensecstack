from flask_sqlalchemy import SQLAlchemy
import redis as redis_lib

db = SQLAlchemy()
redis_client: redis_lib.Redis | None = None


def init_extensions(app) -> None:
    db.init_app(app)

    global redis_client
    redis_client = redis_lib.from_url(
        app.config['REDIS_URL'],
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )
