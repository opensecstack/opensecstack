from flask import Blueprint, request, jsonify, g
from sqlalchemy.exc import IntegrityError
from ..extensions import db
from ..models import Organisation
from ..auth import require_auth, require_scope
from ..audit import write_audit

organisations_bp = Blueprint('organisations', __name__)

VALID_SIZES = {'micro', 'small', 'medium', 'large'}
VALID_ENTITY_TYPES = {'essential', 'important'}


def _paginate(query, page, per_page):
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total


# ------------------------------------------------------------------ #
# GET /api/v1/organisations                                            #
# ------------------------------------------------------------------ #

@organisations_bp.get('/organisations')
@require_auth
def list_organisations():
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

    # Only return organisations owned by the current actor
    query = (
        db.session.query(Organisation)
        .filter(Organisation.created_by == g.actor)
        .order_by(Organisation.created_at.desc())
    )
    items, total = _paginate(query, page, per_page)

    response = jsonify([o.to_dict() for o in items])
    response.headers['X-Total-Count'] = str(total)
    return response, 200


# ------------------------------------------------------------------ #
# POST /api/v1/organisations                                           #
# ------------------------------------------------------------------ #

@organisations_bp.post('/organisations')
@require_auth
@require_scope('read_write')
def create_organisation():
    data = request.get_json(silent=True) or {}

    name = (data.get('name') or '').strip()
    industry = (data.get('industry') or '').strip()
    country = (data.get('country') or '').strip().upper()

    if not name:
        return jsonify({'error': 'name is required', 'code': 'INVALID_INPUT'}), 400
    if not industry:
        return jsonify({'error': 'industry is required', 'code': 'INVALID_INPUT'}), 400
    if not country or len(country) != 2:
        return jsonify({'error': 'country must be a 2-letter ISO 3166-1 alpha-2 code', 'code': 'INVALID_INPUT'}), 400

    size = data.get('size', 'medium')
    if size not in VALID_SIZES:
        return jsonify({'error': f'size must be one of: {", ".join(sorted(VALID_SIZES))}', 'code': 'INVALID_INPUT'}), 400

    entity_type = data.get('entity_type', 'important')
    if entity_type not in VALID_ENTITY_TYPES:
        return jsonify({'error': f'entity_type must be one of: {", ".join(sorted(VALID_ENTITY_TYPES))}', 'code': 'INVALID_INPUT'}), 400

    org = Organisation(
        name=name,
        industry=industry,
        country=country,
        size=size,
        entity_type=entity_type,
        registration_number=data.get('registration_number'),
        contact_email=data.get('contact_email'),
        created_by=g.actor,
    )
    db.session.add(org)

    try:
        db.session.flush()  # get the generated id before audit write
        write_audit(
            db.session,
            action='organisation_created',
            actor=g.actor,
            resource_type='organisation',
            resource_id=org.id,
            risk_class='INFO',
            metadata={'name': org.name, 'entity_type': org.entity_type},
            obj=org.to_dict(),
        )
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'An organisation with this name already exists', 'code': 'CONFLICT'}), 409

    return jsonify(org.to_dict()), 201


# ------------------------------------------------------------------ #
# GET /api/v1/organisations/<id>                                       #
# ------------------------------------------------------------------ #

@organisations_bp.get('/organisations/<uuid:org_id>')
@require_auth
def get_organisation(org_id):
    org = db.session.get(Organisation, org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404
    if org.created_by is not None and org.created_by != g.actor:
        return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403
    return jsonify(org.to_dict()), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/organisations/<id>                                     #
# ------------------------------------------------------------------ #

@organisations_bp.patch('/organisations/<uuid:org_id>')
@require_auth
@require_scope('read_write')
def update_organisation(org_id):
    org = db.session.get(Organisation, org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404
    if org.created_by is not None and org.created_by != g.actor:
        return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403

    data = request.get_json(silent=True) or {}
    before = org.to_dict()

    if 'name' in data:
        org.name = data['name'].strip()
    if 'industry' in data:
        org.industry = data['industry'].strip()
    if 'country' in data:
        c = data['country'].strip().upper()
        if len(c) != 2:
            return jsonify({'error': 'country must be 2 letters', 'code': 'INVALID_INPUT'}), 400
        org.country = c
    if 'size' in data:
        if data['size'] not in VALID_SIZES:
            return jsonify({'error': f'size must be one of: {", ".join(sorted(VALID_SIZES))}', 'code': 'INVALID_INPUT'}), 400
        org.size = data['size']
    if 'entity_type' in data:
        if data['entity_type'] not in VALID_ENTITY_TYPES:
            return jsonify({'error': f'entity_type must be one of: {", ".join(sorted(VALID_ENTITY_TYPES))}', 'code': 'INVALID_INPUT'}), 400
        org.entity_type = data['entity_type']
    if 'registration_number' in data:
        org.registration_number = data['registration_number']
    if 'contact_email' in data:
        org.contact_email = data['contact_email']

    write_audit(
        db.session,
        action='organisation_updated',
        actor=g.actor,
        resource_type='organisation',
        resource_id=org.id,
        risk_class='INFO',
        metadata={'before': before, 'after': org.to_dict()},
    )
    db.session.commit()
    return jsonify(org.to_dict()), 200


# ------------------------------------------------------------------ #
# DELETE /api/v1/organisations/<id>                                    #
# ------------------------------------------------------------------ #

@organisations_bp.delete('/organisations/<uuid:org_id>')
@require_auth
@require_scope('read_write')
def delete_organisation(org_id):
    org = db.session.get(Organisation, org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404
    if org.created_by is not None and org.created_by != g.actor:
        return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403

    write_audit(
        db.session,
        action='organisation_deleted',
        actor=g.actor,
        resource_type='organisation',
        resource_id=org.id,
        risk_class='WARNING',
        metadata={'name': org.name},
        obj=org.to_dict(),
    )
    db.session.delete(org)
    db.session.commit()
    return '', 204
