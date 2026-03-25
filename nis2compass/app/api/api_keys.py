import hashlib
import secrets
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..models import ApiKey
from ..auth import require_auth, require_scope
from ..audit import write_audit

api_keys_bp = Blueprint('api_keys', __name__)

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
    keys = db.session.query(ApiKey).filter(ApiKey.created_by == g.actor).order_by(ApiKey.created_at.desc()).all()
    return jsonify([k.to_dict() for k in keys]), 200


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

    # Generate a cryptographically random key — shown ONCE, never again
    plaintext = f'nis2_{secrets.token_hex(32)}'
    key_hash = _hash_key(plaintext)

    api_key = ApiKey(
        key_hash=key_hash,
        label=label,
        scope=scope,
        created_by=g.actor,
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
    db.session.commit()

    # Return the plaintext key ONCE in the response — it is never stored
    result = api_key.to_dict()
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
    if api_key.created_by is not None and api_key.created_by != g.actor:
        return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403

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
