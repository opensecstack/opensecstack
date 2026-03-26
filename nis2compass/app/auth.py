import hmac
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, g, current_app
from .audit import write_audit


def _constant_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def validate_api_key(api_key: str) -> tuple[bool, str]:
    """
    Check the provided key against DB api_keys table.
    Falls back to NIS2_API_KEYS env var list for bootstrapping
    (used when no DB keys exist yet, e.g. first run).

    Returns a (valid: bool, scope: str) tuple.
    Env-var bootstrap keys always get 'read_write' scope.
    """
    import hashlib

    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()

    # Try database first (inside app context)
    try:
        from .models import ApiKey
        from .extensions import db

        record = (
            db.session.query(ApiKey)
            .filter(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
            .first()
        )
        if record is not None:
            # Reject expired keys
            if record.expires_at is not None and record.expires_at <= datetime.now(timezone.utc):
                return False, 'read_write'
            # Mark last_used_at dirty; the route's normal transaction commit
            # will persist this — no explicit commit here to avoid mid-request
            # transaction boundaries.
            record.last_used_at = datetime.now(timezone.utc)
            write_audit(
                db.session,
                action='api_key_used',
                actor=record.created_by or str(record.id),
                resource_type='api_keys',
                resource_id=record.id,
                risk_class='INFO',
                metadata={'label': record.label, 'scope': record.scope},
            )
            return True, record.scope

        # No DB key matched — fall through to env-var bootstrap keys
        current_app.logger.debug(
            'API key not found in DB; checking bootstrap env-var keys'
        )
    except Exception as exc:
        # DB unavailable — revocation state cannot be verified.
        current_app.logger.error(
            'DB unavailable during API key validation — revocation state unverifiable, '
            'falling back to bootstrap env-var keys: %s', exc
        )
        # In production, fail closed: do not allow access when we cannot
        # confirm that the key has not been revoked.
        if current_app.config.get('NIS2_ENV') == 'production':
            return False, None

    # Bootstrap fallback: env-var keys (constant-time comparison).
    # Only reached in non-production environments when the DB is unavailable,
    # or in any environment when no DB record matched (normal first-run path).
    for valid_key in current_app.config.get('API_KEYS', []):
        if _constant_eq(api_key, valid_key):
            return True, 'read_write'

    return False, 'read_write'


def issue_jwt(identity: str, scope: str = 'read_write') -> tuple[str, datetime]:
    """Sign and return a JWT for the given identity plus its expiry datetime."""
    secret = current_app.config['JWT_SECRET']
    ttl = current_app.config['JWT_TTL']
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    payload = {
        'sub': identity,
        'iat': datetime.now(timezone.utc),
        'exp': expires_at,
        'scope': scope,
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
    except jwt.InvalidTokenError as e:
        current_app.logger.warning('JWT validation failed: %s', type(e).__name__)
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
        # Default to 'read_write' for tokens issued before scope was tracked
        g.token_scope = payload.get('scope', 'read_write')
        return f(*args, **kwargs)
    return decorated


def require_scope(scope: str):
    """Decorator factory that enforces a minimum scope on a route.

    Must be applied *after* @require_auth (i.e. listed below it), so that
    g.token_scope is already set when this check runs.

    Usage::

        @bp.post('/resource')
        @require_auth
        @require_scope('read_write')
        def create_resource():
            ...

    Supported scopes (in ascending privilege order):
      'read'       – read-only operations
      'read_write' – full read/write access
    """
    _SCOPE_RANK = {'read': 0, 'read_write': 1}

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token_scope = getattr(g, 'token_scope', 'read_write')
            required_rank = _SCOPE_RANK.get(scope, 1)
            token_rank = _SCOPE_RANK.get(token_scope, -1)
            if token_rank < required_rank:
                return jsonify({
                    'error': 'Insufficient scope for this operation',
                    'code': 'FORBIDDEN',
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
