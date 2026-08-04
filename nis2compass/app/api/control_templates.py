from flask import Blueprint, jsonify, request

from ..auth import require_auth
from ..extensions import db
from ..models import ControlTemplate

control_templates_bp = Blueprint("control_templates", __name__)

_VALID_FRAMEWORKS = frozenset({"nis2", "soc2", "iso27001"})


@control_templates_bp.get("/control-templates")
@require_auth
def list_control_templates():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (TypeError, ValueError):
        return jsonify({"error": "page and per_page must be integers", "code": "INVALID_INPUT"}), 400

    framework = request.args.get("framework")
    if framework is not None and framework not in _VALID_FRAMEWORKS:
        return (
            jsonify(
                {
                    "error": f"unsupported framework: {framework!r}. Must be one of: nis2, soc2, iso27001",
                    "code": "INVALID_INPUT",
                }
            ),
            400,
        )

    query = db.session.query(ControlTemplate).order_by(ControlTemplate.measure_ref)
    if framework is not None:
        query = query.filter(ControlTemplate.framework == framework)

    total = query.count()
    templates = query.offset((page - 1) * per_page).limit(per_page).all()
    response = jsonify([t.to_dict() for t in templates])
    response.headers["X-Total-Count"] = str(total)
    return response, 200
