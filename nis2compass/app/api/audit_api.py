import uuid as uuid_lib
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..models import AuditLog
from ..auth import require_auth

audit_api_bp = Blueprint('audit_api', __name__)


@audit_api_bp.get('/audit')
@require_auth
def list_audit():
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

    # C1: restrict to entries where the caller is the actor — audit entries are
    # written with the actor who made the change, so showing only your own
    # entries is correct and sufficient.
    query = db.session.query(AuditLog).filter(AuditLog.actor == g.actor)

    if action := request.args.get('action'):
        query = query.filter(AuditLog.action == action)
    if resource_type := request.args.get('resource_type'):
        query = query.filter(AuditLog.resource_type == resource_type)
    if resource_id := request.args.get('resource_id'):
        try:
            uuid_lib.UUID(resource_id)
        except (ValueError, AttributeError):
            return jsonify({'error': 'invalid resource_id format', 'code': 'INVALID_INPUT'}), 400
        query = query.filter(AuditLog.resource_id == resource_id)
    if risk_class := request.args.get('risk_class'):
        query = query.filter(AuditLog.risk_class == risk_class)
    if after := request.args.get('after'):
        try:
            after_dt = datetime.fromisoformat(after.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp > after_dt)
        except ValueError:
            return jsonify({'error': 'after must be an ISO 8601 timestamp', 'code': 'INVALID_INPUT'}), 400

    query = query.order_by(AuditLog.timestamp.desc())
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    response = jsonify([e.to_dict() for e in items])
    response.headers['X-Total-Count'] = str(total)
    return response, 200


@audit_api_bp.get('/audit/<uuid:entry_id>')
@require_auth
def get_audit_entry(entry_id):
    entry = db.session.get(AuditLog, entry_id)
    if entry is None:
        return jsonify({'error': 'Audit entry not found', 'code': 'NOT_FOUND'}), 404
    # C2: do not leak existence of entries belonging to other actors
    if entry.actor != g.actor:
        return jsonify({'error': 'Audit entry not found', 'code': 'NOT_FOUND'}), 404
    return jsonify(entry.to_dict()), 200
