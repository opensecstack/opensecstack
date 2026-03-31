import re
from flask import Blueprint, request, jsonify, g
from sqlalchemy.exc import IntegrityError
from ..extensions import db
from ..models import Organisation
from ..auth import require_auth, require_scope
from ..audit import write_audit
from .assessments import _check_org_access

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

organisations_bp = Blueprint('organisations', __name__)


@organisations_bp.before_request
def require_json_content_type():
    if request.method in ('POST', 'PUT', 'PATCH'):
        ct = request.content_type or ''
        if ct and not ct.startswith('application/json'):
            return jsonify({'error': 'Content-Type must be application/json', 'code': 'UNSUPPORTED_MEDIA_TYPE'}), 415

VALID_SIZES = {'micro', 'small', 'medium', 'large'}
VALID_ENTITY_TYPES = {'essential', 'important'}

_ISO3166_ALPHA2: frozenset = frozenset({
    'AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT',
    'AZ', 'BS', 'BH', 'BD', 'BB', 'BY', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BQ', 'BA', 'BW',
    'BV', 'BR', 'IO', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'KY', 'CF', 'TD', 'CL',
    'CN', 'CX', 'CC', 'CO', 'KM', 'CG', 'CD', 'CK', 'CR', 'CI', 'HR', 'CU', 'CW', 'CY', 'CZ',
    'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ',
    'FI', 'FR', 'GF', 'PF', 'TF', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GP',
    'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'VA', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID',
    'IR', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'KP', 'KR',
    'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MO', 'MG', 'MW', 'MY',
    'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT', 'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MS',
    'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MK',
    'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR',
    'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN', 'LC', 'MF', 'PM', 'VC', 'WS', 'SM', 'ST',
    'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SX', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'SS', 'ES',
    'LK', 'SD', 'SR', 'SJ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO',
    'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UM', 'UY', 'UZ', 'VU',
    'VE', 'VN', 'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW', 'XK',
})


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

    # Return organisations owned by the current actor plus ownerless orgs
    # (created_by IS NULL) that can be claimed via the CAS mechanism.
    query = (
        db.session.query(Organisation)
        .filter(db.or_(Organisation.created_by == g.actor, Organisation.created_by == None))
        .order_by(Organisation.created_at.desc())
    )
    items, total = _paginate(query, page, per_page)

    response = jsonify({
        'data': [o.to_dict() for o in items],
        'total': total,
        'page': page,
        'per_page': per_page,
    })
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
    if len(name) > 255:
        return jsonify({'error': 'name must not exceed 255 characters', 'code': 'INVALID_INPUT'}), 400
    if not industry:
        return jsonify({'error': 'industry is required', 'code': 'INVALID_INPUT'}), 400
    if len(industry) > 100:
        return jsonify({'error': 'industry must not exceed 100 characters', 'code': 'INVALID_INPUT'}), 400
    if not country or len(country) != 2:
        return jsonify({'error': 'country must be a 2-letter ISO 3166-1 alpha-2 code', 'code': 'INVALID_INPUT'}), 400
    if country.upper() not in _ISO3166_ALPHA2:
        return jsonify({'error': 'Invalid ISO 3166-1 alpha-2 country code', 'code': 'INVALID_INPUT'}), 400

    size = data.get('size', 'medium')
    if size not in VALID_SIZES:
        return jsonify({'error': f'size must be one of: {", ".join(sorted(VALID_SIZES))}', 'code': 'INVALID_INPUT'}), 400

    entity_type = data.get('entity_type', 'important')
    if entity_type not in VALID_ENTITY_TYPES:
        return jsonify({'error': f'entity_type must be one of: {", ".join(sorted(VALID_ENTITY_TYPES))}', 'code': 'INVALID_INPUT'}), 400

    contact_email = data.get('contact_email')
    if contact_email is not None:
        if len(contact_email) > 254:
            return jsonify({'error': 'contact_email must not exceed 254 characters', 'code': 'INVALID_INPUT'}), 400
        if not _EMAIL_RE.match(contact_email):
            return jsonify({'error': 'contact_email is not a valid email address', 'code': 'INVALID_INPUT'}), 400

    registration_number = data.get('registration_number')
    if registration_number is not None and len(registration_number) > 100:
        return jsonify({'error': 'registration_number must not exceed 100 characters', 'code': 'INVALID_INPUT'}), 400

    org = Organisation(
        name=name,
        industry=industry,
        country=country,
        size=size,
        entity_type=entity_type,
        registration_number=registration_number,
        contact_email=contact_email,
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
    except IntegrityError as e:
        db.session.rollback()
        # Organisation names are unique per actor (per-tenant), not globally.
        # Two different actors may have organisations with the same name.
        # The unique constraint is on (name, created_by) — see schema.sql
        # idx_organisations_name.
        if hasattr(e, 'orig') and e.orig is not None and getattr(e.orig, 'pgcode', None) == '23505':
            return jsonify({'error': 'An organisation with this name already exists for your account', 'code': 'CONFLICT'}), 409
        raise

    return jsonify(org.to_dict()), 201


# ------------------------------------------------------------------ #
# GET /api/v1/organisations/<id>                                       #
# ------------------------------------------------------------------ #

@organisations_bp.get('/organisations/<uuid:org_id>')
@require_auth
def get_organisation(org_id):
    err = _check_org_access(org_id)
    if err:
        return err
    org = db.session.get(Organisation, org_id)
    return jsonify(org.to_dict()), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/organisations/<id>                                     #
# ------------------------------------------------------------------ #

@organisations_bp.patch('/organisations/<uuid:org_id>')
@require_auth
@require_scope('read_write')
def update_organisation(org_id):
    err = _check_org_access(org_id)
    if err:
        return err
    org = db.session.get(Organisation, org_id)

    data = request.get_json(silent=True) or {}
    before = org.to_dict()

    if 'name' in data:
        name = data['name'].strip()
        if not name:
            return jsonify({'error': 'name must not be empty', 'code': 'INVALID_INPUT'}), 400
        if len(name) > 255:
            return jsonify({'error': 'name must not exceed 255 characters', 'code': 'INVALID_INPUT'}), 400
        org.name = name
    if 'industry' in data:
        industry = data['industry'].strip()
        if not industry:
            return jsonify({'error': 'industry must not be empty', 'code': 'INVALID_INPUT'}), 400
        if len(industry) > 100:
            return jsonify({'error': 'industry must not exceed 100 characters', 'code': 'INVALID_INPUT'}), 400
        org.industry = industry
    if 'country' in data:
        c = data['country'].strip().upper()
        if not c:
            return jsonify({'error': 'country must not be empty', 'code': 'INVALID_INPUT'}), 400
        if len(c) != 2:
            return jsonify({'error': 'country must be 2 letters', 'code': 'INVALID_INPUT'}), 400
        if c not in _ISO3166_ALPHA2:
            return jsonify({'error': 'Invalid ISO 3166-1 alpha-2 country code', 'code': 'INVALID_INPUT'}), 400
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
        reg_num = data['registration_number']
        if reg_num is not None and len(reg_num) > 100:
            return jsonify({'error': 'registration_number must not exceed 100 characters', 'code': 'INVALID_INPUT'}), 400
        org.registration_number = reg_num
    if 'contact_email' in data:
        email = data['contact_email']
        if email is not None:
            if len(email) > 254:
                return jsonify({'error': 'contact_email must not exceed 254 characters', 'code': 'INVALID_INPUT'}), 400
            if not _EMAIL_RE.match(email):
                return jsonify({'error': 'contact_email is not a valid email address', 'code': 'INVALID_INPUT'}), 400
        org.contact_email = email

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
    err = _check_org_access(org_id)
    if err:
        return err
    org = db.session.get(Organisation, org_id)

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
