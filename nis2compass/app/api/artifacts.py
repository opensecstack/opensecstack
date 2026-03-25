import hashlib
import os
import uuid as uuid_lib
from flask import Blueprint, request, jsonify, g, current_app, send_file
from ..extensions import db
from ..models import Assessment, Control, Artifact
from ..auth import require_auth, require_scope
from ..audit import write_audit

artifacts_bp = Blueprint('artifacts', __name__)

VALID_TYPES = {'policy', 'procedure', 'evidence', 'report', 'screenshot', 'log', 'certificate', 'contract'}

ALLOWED_MIME_TYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'text/csv',
    'image/png',
    'image/jpeg',
    'image/gif',
    'application/zip',
    'application/x-zip-compressed',
    'application/json',
    'application/xml',
    'text/xml',
}


def _save_file(file_storage, assessment_id: str) -> tuple[str, str, int, str]:
    """Save uploaded file, return (file_path, sha256_hex, size_bytes, mime_type)."""
    upload_dir = os.path.join(current_app.config['UPLOAD_DIR'], assessment_id)
    os.makedirs(upload_dir, exist_ok=True)

    # Use a UUID-prefixed filename to avoid collisions
    safe_name = f'{uuid_lib.uuid4().hex}_{file_storage.filename}'
    file_path = os.path.join(upload_dir, safe_name)

    sha256 = hashlib.sha256()
    size = 0
    file_storage.stream.seek(0)
    with open(file_path, 'wb') as f:
        for chunk in iter(lambda: file_storage.stream.read(65536), b''):
            sha256.update(chunk)
            f.write(chunk)
            size += len(chunk)

    return file_path, sha256.hexdigest(), size, file_storage.mimetype or 'application/octet-stream'


# ------------------------------------------------------------------ #
# GET /api/v1/assessments/<id>/artifacts                               #
# ------------------------------------------------------------------ #

@artifacts_bp.get('/assessments/<uuid:assessment_id>/artifacts')
@require_auth
def list_artifacts(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404

    query = db.session.query(Artifact).filter(Artifact.assessment_id == assessment_id)
    if control_id := request.args.get('control_id'):
        query = query.filter(Artifact.control_id == control_id)
    if art_type := request.args.get('type'):
        query = query.filter(Artifact.type == art_type)
    query = query.order_by(Artifact.created_at.desc())

    items = query.all()
    response = jsonify([a.to_dict() for a in items])
    response.headers['X-Total-Count'] = str(len(items))
    return response, 200


# ------------------------------------------------------------------ #
# POST /api/v1/assessments/<id>/artifacts                              #
# ------------------------------------------------------------------ #

@artifacts_bp.post('/assessments/<uuid:assessment_id>/artifacts')
@require_auth
@require_scope('read_write')
def upload_artifact(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    if assessment.status == 'archived':
        return jsonify({'error': 'Archived assessments are read-only', 'code': 'INVALID_INPUT'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'file field is required', 'code': 'INVALID_INPUT'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected', 'code': 'INVALID_INPUT'}), 400

    # MIME type validation — use the content_type supplied by the client (no
    # system-level libmagic dependency required).
    content_type = (file.content_type or '').split(';')[0].strip().lower()
    if content_type not in ALLOWED_MIME_TYPES:
        return jsonify({
            'error': 'Unsupported file type',
            'code': 'UNSUPPORTED_MEDIA_TYPE',
            'allowed_types': sorted(ALLOWED_MIME_TYPES),
        }), 415

    art_type = request.form.get('type', '').strip()
    if art_type not in VALID_TYPES:
        return jsonify({'error': f'type must be one of: {", ".join(sorted(VALID_TYPES))}', 'code': 'INVALID_INPUT'}), 400

    control_id = request.form.get('control_id')
    if control_id:
        control = db.session.get(Control, control_id)
        if control is None or str(control.assessment_id) != str(assessment_id):
            return jsonify({'error': 'Control not found in this assessment', 'code': 'NOT_FOUND'}), 404

    file_path, file_hash, size_bytes, mime_type = _save_file(file, str(assessment_id))

    artifact = Artifact(
        assessment_id=assessment_id,
        control_id=control_id,
        type=art_type,
        filename=file.filename,
        file_path=file_path,
        hash=file_hash,
        size_bytes=size_bytes,
        mime_type=mime_type,
        description=request.form.get('description'),
        created_by=g.actor,
    )
    db.session.add(artifact)
    db.session.flush()

    write_audit(
        db.session,
        action='artifact_uploaded',
        actor=g.actor,
        resource_type='artifact',
        resource_id=artifact.id,
        risk_class='INFO',
        metadata={'filename': artifact.filename, 'type': artifact.type, 'hash': artifact.hash, 'size_bytes': size_bytes},
    )
    db.session.commit()
    return jsonify(artifact.to_dict()), 201


# ------------------------------------------------------------------ #
# GET /api/v1/artifacts/<id>                                           #
# ------------------------------------------------------------------ #

@artifacts_bp.get('/artifacts/<uuid:artifact_id>')
@require_auth
def get_artifact(artifact_id):
    artifact = db.session.get(Artifact, artifact_id)
    if artifact is None:
        return jsonify({'error': 'Artifact not found', 'code': 'NOT_FOUND'}), 404
    return jsonify(artifact.to_dict()), 200


# ------------------------------------------------------------------ #
# GET /api/v1/artifacts/<id>/download                                  #
# ------------------------------------------------------------------ #

@artifacts_bp.get('/artifacts/<uuid:artifact_id>/download')
@require_auth
def download_artifact(artifact_id):
    artifact = db.session.get(Artifact, artifact_id)
    if artifact is None:
        return jsonify({'error': 'Artifact not found', 'code': 'NOT_FOUND'}), 404

    if not artifact.file_path or not os.path.isfile(artifact.file_path):
        return jsonify({'error': 'File no longer available', 'code': 'FILE_NOT_FOUND'}), 410

    write_audit(
        db.session,
        action='artifact_downloaded',
        actor=g.actor,
        resource_type='artifact',
        resource_id=artifact.id,
        risk_class='INFO',
        metadata={'filename': artifact.filename, 'type': artifact.type, 'hash': artifact.hash},
    )
    db.session.commit()

    return send_file(
        artifact.file_path,
        mimetype=artifact.mime_type,
        as_attachment=True,
        download_name=artifact.filename,
    )


# ------------------------------------------------------------------ #
# DELETE /api/v1/artifacts/<id>                                        #
# ------------------------------------------------------------------ #

@artifacts_bp.delete('/artifacts/<uuid:artifact_id>')
@require_auth
@require_scope('read_write')
def delete_artifact(artifact_id):
    artifact = db.session.get(Artifact, artifact_id)
    if artifact is None:
        return jsonify({'error': 'Artifact not found', 'code': 'NOT_FOUND'}), 404

    write_audit(
        db.session,
        action='artifact_deleted',
        actor=g.actor,
        resource_type='artifact',
        resource_id=artifact.id,
        risk_class='WARNING',
        metadata={'filename': artifact.filename, 'hash': artifact.hash},
    )
    db.session.delete(artifact)
    db.session.commit()
    return '', 204
