from sqlalchemy import text
from flask import Blueprint, jsonify

from ..extensions import db, redis_client

health_bp = Blueprint('health', __name__)

VERSION = '1.0.0'


@health_bp.get('/health')
def health():
    checks: dict = {'status': 'ok', 'version': VERSION}

    # Database connectivity
    try:
        db.session.execute(text('SELECT 1'))
        checks['db'] = 'ok'
    except Exception:
        checks['db'] = 'error'
        checks['status'] = 'degraded'

    # Redis connectivity
    rc = redis_client
    if rc is not None:
        try:
            rc.ping()
            checks['redis'] = 'ok'
        except Exception:
            checks['redis'] = 'error'
            checks['status'] = 'degraded'
    else:
        checks['redis'] = 'unavailable'

    status_code = 200 if checks['status'] == 'ok' else 503
    return jsonify(checks), status_code
