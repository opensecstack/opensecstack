import hashlib
from flask import Blueprint, request, jsonify, current_app, g
from ..auth import validate_api_key, issue_jwt

auth_bp = Blueprint('auth_api', __name__)


@auth_bp.post('/auth/token')
def token():
    """Exchange an API key for a short-lived JWT."""
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key', '').strip()

    if not api_key:
        return jsonify({'error': 'api_key is required', 'code': 'INVALID_INPUT'}), 400

    valid, scope = validate_api_key(api_key)
    if not valid:
        return jsonify({'error': 'Invalid API key', 'code': 'UNAUTHORIZED'}), 401

    # Use the DB key UUID when available (set by validate_api_key for DB-backed keys).
    # Fall back to a hash prefix for bootstrap env-var keys that have no DB record.
    api_key_id = getattr(g, 'api_key_id', None)
    if api_key_id:
        identity = 'api_key:' + api_key_id
    else:
        identity = 'api_key:' + hashlib.sha256(api_key.encode()).hexdigest()[:16]
    jwt_token, expires_at = issue_jwt(identity, scope=scope)

    return jsonify({
        'token': jwt_token,
        'expires_at': expires_at.isoformat(),
    }), 200
