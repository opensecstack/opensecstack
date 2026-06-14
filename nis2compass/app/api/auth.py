import hashlib
from datetime import datetime, timezone

import jwt
from flask import Blueprint, request, jsonify, current_app, g

from ..auth import (
    validate_api_key,
    issue_jwt,
    create_access_token,
    create_refresh_token,
    verify_token,
    revoke_token,
)

auth_bp = Blueprint('auth_api', __name__)


@auth_bp.post('/auth/token')
def token():
    """Exchange an API key for an access + refresh token pair."""
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key', '').strip()

    if not api_key:
        return jsonify({'error': 'api_key is required', 'code': 'INVALID_INPUT'}), 400

    valid, scope, role = validate_api_key(api_key)
    if not valid:
        return jsonify({'error': 'Invalid API key', 'code': 'UNAUTHORIZED'}), 401

    # Use the DB key UUID when available (set by validate_api_key for DB-backed keys).
    # Fall back to a hash prefix for bootstrap env-var keys that have no DB record.
    api_key_id = getattr(g, 'api_key_id', None)
    if api_key_id:
        identity = 'api_key:' + api_key_id
        # Commit the last_used_at update and api_key_used audit entry that
        # validate_api_key wrote to the session — without this commit they are
        # silently rolled back at request teardown.
        from ..extensions import db as _db
        try:
            _db.session.commit()
        except Exception:
            _db.session.rollback()
    else:
        identity = 'api_key:' + hashlib.sha256(api_key.encode()).hexdigest()[:16]

    access_token, access_expires_at = create_access_token(subject=identity, role=role)
    refresh_token, _ = create_refresh_token(subject=identity, role=role)

    ttl_minutes = current_app.config.get('JWT_ACCESS_TTL_MINUTES', 15)
    expires_in = ttl_minutes * 60

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': expires_in,
    }), 200


@auth_bp.post('/auth/token/refresh')
def token_refresh():
    """Issue a new access + refresh pair by presenting a valid refresh token.

    The presented refresh token is immediately revoked (rotation) so that
    each token can only be exchanged once.
    """
    data = request.get_json(silent=True) or {}
    raw_token = data.get('refresh_token', '').strip()

    if not raw_token:
        return jsonify({'error': 'refresh_token is required', 'code': 'INVALID_INPUT'}), 400

    try:
        payload = verify_token(raw_token, 'refresh')
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token has expired', 'code': 'UNAUTHORIZED'}), 401
    except jwt.InvalidTokenError as exc:
        return jsonify({'error': str(exc), 'code': 'UNAUTHORIZED'}), 401

    # Rotate: revoke the consumed refresh token
    jti = payload.get('jti')
    exp_raw = payload.get('exp')
    if jti and exp_raw is not None:
        exp_dt = datetime.fromtimestamp(exp_raw, tz=timezone.utc)
        revoke_token(jti, exp_dt)

    subject = payload.get('sub', '')
    role = payload.get('role', 'assessor')

    access_token, _ = create_access_token(subject=subject, role=role)
    refresh_token, _ = create_refresh_token(subject=subject, role=role)

    ttl_minutes = current_app.config.get('JWT_ACCESS_TTL_MINUTES', 15)
    expires_in = ttl_minutes * 60

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': expires_in,
    }), 200


@auth_bp.post('/auth/token/revoke')
def token_revoke():
    """Revoke any token (access or refresh) by its JTI.

    The signature is not verified — only the JTI and expiry are extracted so
    that callers can revoke tokens without needing the secret.  The server
    validates the secret at *use* time; revocation is purely additive.
    """
    data = request.get_json(silent=True) or {}
    raw_token = data.get('token', '').strip()

    if not raw_token:
        return jsonify({'error': 'token is required', 'code': 'INVALID_INPUT'}), 400

    try:
        # Decode without signature verification to extract claims only
        payload = jwt.decode(
            raw_token,
            options={'verify_signature': False},
            algorithms=['HS256'],
        )
    except jwt.InvalidTokenError as exc:
        return jsonify({'error': f'Cannot decode token: {exc}', 'code': 'INVALID_INPUT'}), 400

    jti = payload.get('jti')
    exp_raw = payload.get('exp')

    if not jti or exp_raw is None:
        return jsonify({'error': 'Token is missing jti or exp claims', 'code': 'INVALID_INPUT'}), 400

    exp_dt = datetime.fromtimestamp(exp_raw, tz=timezone.utc)
    revoke_token(jti, exp_dt)

    return '', 204
