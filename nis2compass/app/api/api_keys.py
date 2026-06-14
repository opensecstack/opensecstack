import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..models import ApiKey
from ..auth import require_auth, require_scope
from ..audit import write_audit

api_keys_bp = Blueprint('api_keys', __name__)


@api_keys_bp.before_request
def require_json_content_type():
    if request.method in ('POST', 'PUT', 'PATCH'):
        ct = request.content_type or ''
        if ct and not ct.startswith('application/json'):
            return jsonify({'error': 'Content-Type must be application/json', 'code': 'UNSUPPORTED_MEDIA_TYPE'}), 415

VALID_SCOPES = {'read', 'read_write'}


def _hash_key(plaintext: str) -> str:
    """SHA-256 hex digest of a plaintext API key."""
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()


# ------------------------------------------------------------------ #
# GET /api/v1/api-keys                                                 #
# ------------------------------------------------------------------ #

@api_keys_bp.get('/api-keys')
@require_auth
def list_api_keys():
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

    query = db.session.query(ApiKey).filter(ApiKey.created_by == g.actor).order_by(ApiKey.created_at.desc())
    total = query.count()
    keys = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'data': [k.to_dict() for k in keys],
        'page': page,
        'per_page': per_page,
        'total': total,
    }), 200


# ------------------------------------------------------------------ #
# POST /api/v1/api-keys                                                #
# ------------------------------------------------------------------ #

@api_keys_bp.post('/api-keys')
@require_auth
@require_scope('read_write')
def create_api_key():
    data = request.get_json(silent=True) or {}
    label = (data.get('label') or '').strip() or None
    scope = data.get('scope', 'read_write')

    if scope not in VALID_SCOPES:
        return jsonify({'error': f'scope must be one of: {", ".join(sorted(VALID_SCOPES))}', 'code': 'INVALID_INPUT'}), 400

    expires_at = None
    expires_in_days = data.get('expires_in_days')
    if expires_in_days is not None:
        try:
            expires_in_days = int(expires_in_days)
            if expires_in_days <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({'error': 'expires_in_days must be a positive integer', 'code': 'INVALID_INPUT'}), 400
        if expires_in_days > 365:
            return jsonify({'error': 'expires_in_days must not exceed 365', 'code': 'INVALID_INPUT'}), 400
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    # Generate a cryptographically random key — shown ONCE, never again
    plaintext = f'nis2_{secrets.token_hex(32)}'
    key_hash = _hash_key(plaintext)

    api_key = ApiKey(
        key_hash=key_hash,
        label=label,
        scope=scope,
        created_by=g.actor,
        expires_at=expires_at,
    )
    db.session.add(api_key)
    db.session.flush()

    write_audit(
        db.session,
        action='api_key_created',
        actor=g.actor,
        resource_type='api_key',
        resource_id=api_key.id,
        risk_class='WARNING',
        metadata={'label': label, 'scope': scope},
    )
    result = api_key.to_dict()  # serialize while still attached (before commit detaches)
    db.session.commit()

    # Return the plaintext key ONCE in the response — it is never stored
    result['key'] = plaintext
    result['warning'] = 'This is the only time the plaintext key will be shown. Store it securely.'
    return jsonify(result), 201


# ------------------------------------------------------------------ #
# DELETE /api/v1/api-keys/<id>  (revoke)                              #
# ------------------------------------------------------------------ #

@api_keys_bp.delete('/api-keys/<uuid:key_id>')
@require_auth
@require_scope('read_write')
def revoke_api_key(key_id):
    api_key = db.session.get(ApiKey, key_id)
    if api_key is None:
        return jsonify({'error': 'API key not found', 'code': 'NOT_FOUND'}), 404
    if api_key.created_by != g.actor:
        return jsonify({'error': 'Forbidden', 'code': 'FORBIDDEN'}), 403

    api_key.is_active = False
    write_audit(
        db.session,
        action='api_key_revoked',
        actor=g.actor,
        resource_type='api_key',
        resource_id=api_key.id,
        risk_class='WARNING',
        metadata={'label': api_key.label},
    )
    db.session.commit()
    return '', 204
