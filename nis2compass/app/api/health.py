from flask import Blueprint, jsonify

health_bp = Blueprint('health', __name__)

VERSION = '1.0.0'


@health_bp.get('/health')
def health():
    return jsonify({'status': 'ok', 'version': VERSION}), 200
