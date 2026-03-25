from flask import Blueprint, request, jsonify, current_app
from ..auth import validate_api_key, issue_jwt

auth_bp = Blueprint('auth_api', __name__)


@auth_bp.post('/auth/token')
def token():
    """Exchange an API key for a short-lived JWT."""
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key', '').strip()

    if not api_key:
        return jsonify({'error': 'api_key is required', 'code': 'INVALID_INPUT'}), 400

    if not validate_api_key(api_key):
        return jsonify({'error': 'Invalid API key', 'code': 'UNAUTHORIZED'}), 401

    # Use a stable identity — in the future this can be looked up from a keys table
    identity = f'api_key:{api_key[:8]}...'
    jwt_token, expires_at = issue_jwt(identity)

    return jsonify({
        'token': jwt_token,
        'expires_at': expires_at.isoformat(),
    }), 200
