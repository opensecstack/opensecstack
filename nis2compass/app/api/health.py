from sqlalchemy import text
from flask import Blueprint, jsonify, request

from ..extensions import db, redis_client
from ..auth import decode_jwt

health_bp = Blueprint('health', __name__)

VERSION = '1.0.0'


def _collect_checks() -> dict:
    """Run connectivity checks and return a detail dict."""
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

    return checks


@health_bp.get('/health')
def health():
    """Public liveness probe — returns only aggregate status (H10)."""
    checks = _collect_checks()
    aggregate = checks.get('status', 'degraded')
    status_code = 200 if aggregate == 'ok' else 503
    return jsonify({'status': aggregate}), status_code


@health_bp.get('/health/detail')
def health_detail():
    """Detailed health check — requires a valid Bearer JWT (H10)."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header', 'code': 'UNAUTHORIZED'}), 401
    token = auth_header[len('Bearer '):]
    if decode_jwt(token) is None:
        return jsonify({'error': 'Token is invalid or expired', 'code': 'UNAUTHORIZED'}), 401

    checks = _collect_checks()
    status_code = 200 if checks.get('status') == 'ok' else 503
    return jsonify(checks), status_code
