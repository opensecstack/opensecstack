from flask import Blueprint, jsonify, request
from ..extensions import db
from ..models import ControlTemplate
from ..auth import require_auth

control_templates_bp = Blueprint('control_templates', __name__)


@control_templates_bp.get('/control-templates')
@require_auth
def list_control_templates():
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
    except (TypeError, ValueError):
        return jsonify({'error': 'page and per_page must be integers', 'code': 'INVALID_INPUT'}), 400

    query = db.session.query(ControlTemplate).order_by(ControlTemplate.measure_ref)
    total = query.count()
    templates = query.offset((page - 1) * per_page).limit(per_page).all()
    response = jsonify([t.to_dict() for t in templates])
    response.headers['X-Total-Count'] = total
    return response, 200
