from flask import Blueprint, jsonify
from ..extensions import db
from ..models import ControlTemplate
from ..auth import require_auth

control_templates_bp = Blueprint('control_templates', __name__)


@control_templates_bp.get('/control-templates')
@require_auth
def list_control_templates():
    templates = (
        db.session.query(ControlTemplate)
        .order_by(ControlTemplate.measure_ref)
        .all()
    )
    return jsonify([t.to_dict() for t in templates]), 200
