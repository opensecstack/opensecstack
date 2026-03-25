import hmac
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, g, current_app


def _constant_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def validate_api_key(api_key: str) -> bool:
    """
    Check the provided key against DB api_keys table.
    Falls back to NIS2_API_KEYS env var list for bootstrapping
    (used when no DB keys exist yet, e.g. first run).
    """
    import hashlib

    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()

    # Try database first (inside app context)
    try:
        from .models import ApiKey
        from .extensions import db
        from sqlalchemy import text as sa_text

        record = (
            db.session.query(ApiKey)
            .filter(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
            .first()
        )
        if record is not None:
            # Update last_used_at without triggering audit
            record.last_used_at = datetime.now(timezone.utc)
            db.session.commit()
            return True

        # If DB has any active keys, don't fall through to env-var
        if db.session.query(ApiKey).filter(ApiKey.is_active == True).count() > 0:
            return False
    except Exception:
        # DB unavailable — fall through to env-var check
        pass

    # Bootstrap fallback: env-var keys (constant-time comparison)
    for valid_key in current_app.config.get('API_KEYS', []):
        if _constant_eq(api_key, valid_key):
            return True

    return False


def issue_jwt(identity: str) -> tuple[str, datetime]:
    """Sign and return a JWT for the given identity plus its expiry datetime."""
    secret = current_app.config['JWT_SECRET']
    ttl = current_app.config['JWT_TTL']
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    payload = {
        'sub': identity,
        'iat': datetime.now(timezone.utc),
        'exp': expires_at,
    }
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token, expires_at


def decode_jwt(token: str) -> dict | None:
    """Decode and validate a JWT. Returns payload dict or None on failure."""
    secret = current_app.config['JWT_SECRET']
    try:
        return jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Decorator that enforces Bearer JWT authentication on a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header', 'code': 'UNAUTHORIZED'}), 401
        token = auth_header[len('Bearer '):]
        payload = decode_jwt(token)
        if payload is None:
            return jsonify({'error': 'Token is invalid or expired', 'code': 'UNAUTHORIZED'}), 401
        g.actor = payload.get('sub', 'unknown')
        return f(*args, **kwargs)
    return decorated
