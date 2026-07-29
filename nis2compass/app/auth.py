import hmac
import uuid
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, g, current_app
from .audit import write_audit


def _constant_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def validate_api_key(api_key: str) -> tuple[bool, str, str]:
    """
    Check the provided key against DB api_keys table.
    Falls back to NIS2_API_KEYS env var list for bootstrapping
    (used when no DB keys exist yet, e.g. first run).

    Returns a (valid: bool, scope: str, role: str) tuple.
    Env-var bootstrap keys always get 'read_write' scope and 'admin' role.
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
                return False, 'read_write', 'viewer'
            # Mark last_used_at dirty; the route's normal transaction commit
            # will persist this — no explicit commit here to avoid mid-request
            # transaction boundaries.
            record.last_used_at = datetime.now(timezone.utc)
            # Store the key's UUID on g so JWT issuance can use it as identity.
            g.api_key_id = str(record.id)
            write_audit(
                db.session,
                action='api_key_used',
                actor=record.created_by or str(record.id),
                resource_type='api_keys',
                resource_id=record.id,
                risk_class='INFO',
                metadata={'label': record.label, 'scope': record.scope, 'role': record.role},
            )
            return True, record.scope, record.role

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
        # Roll back the failed transaction so the session is clean if the
        # caller later uses db.session in the same request.
        try:
            from .extensions import db as _db
            _db.session.rollback()
        except Exception:
            pass
        # In production, fail closed: do not allow access when we cannot
        # confirm that the key has not been revoked.
        if current_app.config.get('ENV') == 'production':
            return False, None, None

    # Bootstrap fallback: env-var keys (constant-time comparison).
    # Only reached in non-production environments when the DB is unavailable,
    # or in any environment when no DB record matched (normal first-run path).
    for valid_key in current_app.config.get('API_KEYS', []):
        if _constant_eq(api_key, valid_key):
            return True, 'read_write', 'admin'

    return False, 'read_write', 'viewer'


def issue_jwt(identity: str, scope: str = 'read_write', role: str = 'assessor',
              api_key_id: str | None = None) -> tuple[str, datetime]:
    """Sign and return a JWT for the given identity plus its expiry datetime."""
    secret = current_app.config['JWT_SECRET']
    ttl = current_app.config['JWT_TTL']
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    payload = {
        'sub': identity,
        'iat': datetime.now(timezone.utc),
        'exp': expires_at,
        'scope': scope,
        'role': role,
    }
    if api_key_id:
        payload['kid'] = api_key_id
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


# ---------------------------------------------------------------------------
# Access / refresh token pair
# ---------------------------------------------------------------------------

def create_access_token(subject: str, role: str) -> tuple[str, datetime]:
    """Sign and return a short-lived access JWT plus its expiry datetime."""
    secret = current_app.config['JWT_SECRET']
    ttl_minutes = current_app.config.get('JWT_ACCESS_TTL_MINUTES', 15)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=ttl_minutes)
    payload = {
        'sub': subject,
        'role': role,
        'type': 'access',
        'jti': str(uuid.uuid4()),
        'iat': now,
        'exp': expires_at,
    }
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token, expires_at


def create_refresh_token(subject: str, role: str) -> tuple[str, datetime]:
    """Sign and return a long-lived refresh JWT plus its expiry datetime."""
    secret = current_app.config['JWT_SECRET']
    ttl_days = current_app.config.get('JWT_REFRESH_TTL_DAYS', 7)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=ttl_days)
    payload = {
        'sub': subject,
        'role': role,
        'type': 'refresh',
        'jti': str(uuid.uuid4()),
        'iat': now,
        'exp': expires_at,
    }
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token, expires_at


def verify_token(token: str, expected_type: str) -> dict:
    """Validate a JWT's signature, expiry, type claim, and revocation state.

    Returns the decoded payload on success.
    Raises ``jwt.InvalidTokenError`` subclasses on failure so callers can
    convert them to appropriate HTTP responses.
    """
    from .extensions import redis_client

    secret = current_app.config['JWT_SECRET']
    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError('Token has expired')
    except jwt.InvalidTokenError:
        raise

    # Enforce token type
    if payload.get('type') != expected_type:
        raise jwt.InvalidTokenError(
            f'Expected token type {expected_type!r}, got {payload.get("type")!r}'
        )

    # Check revocation via Redis (primary store)
    jti = payload.get('jti')
    if jti:
        revoked = False
        if redis_client is not None:
            try:
                revoked = redis_client.exists(f'revoked_jti:{jti}') > 0
            except Exception as exc:
                current_app.logger.warning(
                    'Redis unavailable during token revocation check — falling back to DB: %s', exc
                )
                revoked = _db_is_revoked(jti)
        else:
            revoked = _db_is_revoked(jti)

        if revoked:
            raise jwt.InvalidTokenError('Token has been revoked')

    return payload


def _db_is_revoked(jti: str) -> bool:
    """Fallback: check the DB revoked_tokens table when Redis is unavailable."""
    try:
        from .models import RevokedToken
        from .extensions import db
        record = db.session.get(RevokedToken, jti)
        if record is None:
            return False
        # Honour expires_at so we match the Redis TTL semantics:
        # a revoked record is only active while its TTL has not elapsed.
        return record.expires_at > datetime.now(timezone.utc)
    except Exception:
        # Cannot confirm revocation — fail open (consistent with existing
        # DB-unavailable behaviour in validate_api_key for non-prod).
        # Roll back the failed transaction so the session is clean for the
        # route handler that will run after require_auth returns.
        try:
            from .extensions import db as _db
            _db.session.rollback()
        except Exception:
            pass
        return False


def revoke_token(jti: str, exp: datetime) -> None:
    """Store jti in the revocation set with TTL = seconds until exp.

    Primary store is Redis; DB table is used as fallback.
    Logs a warning and continues if neither store is available.
    """
    from .extensions import redis_client

    now = datetime.now(timezone.utc)
    # Guard against already-expired tokens — nothing to revoke
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    ttl_seconds = int((exp - now).total_seconds())
    if ttl_seconds <= 0:
        return

    # Try Redis first
    redis_ok = False
    if redis_client is not None:
        try:
            redis_client.setex(f'revoked_jti:{jti}', ttl_seconds, '1')
            redis_ok = True
        except Exception as exc:
            current_app.logger.warning(
                'Redis unavailable during token revocation — falling back to DB: %s', exc
            )

    # DB fallback
    if not redis_ok:
        try:
            from .models import RevokedToken
            from .extensions import db
            record = RevokedToken(
                jti=jti,
                revoked_at=now,
                expires_at=exp,
            )
            db.session.merge(record)
            db.session.commit()
        except Exception as exc:
            current_app.logger.warning(
                'DB fallback for token revocation also failed — token %s not revoked: %s',
                jti, exc,
            )


def require_auth(f):
    """Decorator that enforces Bearer JWT authentication on a route.

    Validates the token as an access token (type claim, expiry, revocation).
    After decoding it also verifies that the originating API key (stored as
    ``kid`` in the JWT claims) has not been revoked or expired since the token
    was issued.  This closes the window where a revoked key could continue to
    operate until the JWT's own ``exp`` elapsed.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header', 'code': 'UNAUTHORIZED'}), 401
        token = auth_header[len('Bearer '):]

        # Stash the raw bearer token for the current request. Needed as
        # CITADEL Kerkese.ActorToken (see app/citadel_client.py) — CITADEL
        # verifies it directly against sinauth's JWKS, so the raw string
        # must be forwarded, not just the parsed claims.
        g.raw_token = token
        g.actor_is_sinauth = False

        sinauth_url = current_app.config.get('SINAUTH_URL', '')
        sinauth_issuer = current_app.config.get('SINAUTH_ISSUER', sinauth_url)

        if sinauth_url:
            from .sinauth import is_rs256_token, verify_sinauth_token
            if is_rs256_token(token):
                payload = verify_sinauth_token(token, sinauth_url, sinauth_issuer)
                if payload is None:
                    return jsonify({'error': 'Token is invalid or expired', 'code': 'UNAUTHORIZED'}), 401
                g.actor = payload.get('sub', 'unknown')
                g.token_scope = 'read_write'  # sinauth tokens get full scope
                g.token_role = payload.get('role', 'assessor')
                g.actor_email = payload.get('email')
                # Real sinauth-issued identity — sub is a sinauth UUID and
                # `token` is a live RS256 bearer CITADEL can verify directly.
                g.actor_is_sinauth = True
                return f(*args, **kwargs)

        try:
            payload = verify_token(token, 'access')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired', 'code': 'UNAUTHORIZED'}), 401
        except jwt.InvalidTokenError:
            # Legacy tokens (no type claim) issued before this change are
            # decoded the old way so existing integrations are not broken.
            payload = decode_jwt(token)
            if payload is None:
                return jsonify({'error': 'Token is invalid or expired', 'code': 'UNAUTHORIZED'}), 401

        # Check that the originating API key is still active + not expired
        kid = payload.get('kid')
        if kid:
            try:
                from .models import ApiKey
                from .extensions import db
                record = db.session.get(ApiKey, kid)
                if record is None or not record.is_active:
                    return jsonify({'error': 'API key revoked', 'code': 'UNAUTHORIZED'}), 401
                if record.expires_at is not None and record.expires_at <= datetime.now(timezone.utc):
                    return jsonify({'error': 'API key expired', 'code': 'UNAUTHORIZED'}), 401
            except Exception:
                # DB unavailable — fall through (fail-open for non-prod).
                # Roll back the failed transaction so the session is clean
                # for the route handler that follows.
                try:
                    from .extensions import db as _db
                    _db.session.rollback()
                except Exception:
                    pass

        g.actor = payload.get('sub', 'unknown')
        g.token_scope = payload.get('scope', 'read_write')
        g.token_role = payload.get('role', 'assessor')
        g.actor_email = payload.get('email')
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


# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

# Ascending privilege: viewer < auditor < assessor < admin
_ROLE_RANK = {
    'viewer': 0,
    'auditor': 1,
    'assessor': 2,
    'admin': 3,
}

VALID_ROLES = frozenset(_ROLE_RANK.keys())


def require_role(*allowed_roles: str):
    """Decorator factory that restricts a route to one or more RBAC roles.

    Must be applied *after* @require_auth so that ``g.token_role`` is set.

    Usage::

        @bp.delete('/organisations/<id>')
        @require_auth
        @require_role('admin')
        def delete_org(id):
            ...

        @bp.get('/audit')
        @require_auth
        @require_role('admin', 'auditor')
        def list_audit():
            ...
    """
    allowed = frozenset(allowed_roles)

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token_role = getattr(g, 'token_role', 'viewer')
            if token_role not in allowed:
                return jsonify({
                    'error': f'Role \'{token_role}\' is not permitted for this operation',
                    'code': 'FORBIDDEN',
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
