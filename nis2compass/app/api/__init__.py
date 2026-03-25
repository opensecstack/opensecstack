from flask import Flask


def register_blueprints(app: Flask) -> None:
    from .health import health_bp
    from .auth import auth_bp
    from .organisations import organisations_bp
    from .control_templates import control_templates_bp
    from .assessments import assessments_bp
    from .controls import controls_bp
    from .artifacts import artifacts_bp
    from .audit_api import audit_api_bp
    from .api_keys import api_keys_bp
    from .openapi import openapi_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp,              url_prefix='/api/v1')
    app.register_blueprint(organisations_bp,     url_prefix='/api/v1')
    app.register_blueprint(control_templates_bp, url_prefix='/api/v1')
    app.register_blueprint(assessments_bp,       url_prefix='/api/v1')
    app.register_blueprint(controls_bp,          url_prefix='/api/v1')
    app.register_blueprint(artifacts_bp,         url_prefix='/api/v1')
    app.register_blueprint(audit_api_bp,         url_prefix='/api/v1')
    app.register_blueprint(api_keys_bp,          url_prefix='/api/v1')
    app.register_blueprint(openapi_bp,           url_prefix='/api/v1')
