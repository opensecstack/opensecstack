"""Structured JSON error handlers — replaces Flask's default HTML pages."""

from flask import jsonify


def register_error_handlers(app):

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({'error': getattr(e, 'description', 'Bad request'), 'code': 'BAD_REQUEST'}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({'error': 'Authentication required', 'code': 'UNAUTHORIZED'}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({'error': 'Insufficient permissions', 'code': 'FORBIDDEN'}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Resource not found', 'code': 'NOT_FOUND'}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({'error': 'Method not allowed', 'code': 'METHOD_NOT_ALLOWED'}), 405

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({'error': 'Rate limit exceeded', 'code': 'RATE_LIMITED'}), 429

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception('Unhandled 500 error')
        return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
