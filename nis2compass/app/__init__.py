from flask import Flask
from .config import Config
from .extensions import init_extensions
from .middleware import apply_middleware


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    init_extensions(app)
    apply_middleware(app)

    from .api import register_blueprints
    register_blueprints(app)

    return app
