from flask import Flask
from .config import Config
from .extensions import init_extensions
from .middleware import apply_middleware


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if not app.config.get('JWT_SECRET') and not app.config.get('DEBUG'):
        raise RuntimeError(
            'NIS2_JWT_SECRET must be set in production. '
            'Generate one with: openssl rand -hex 32'
        )

    init_extensions(app)
    apply_middleware(app)

    from .api import register_blueprints
    register_blueprints(app)

    return app
