import hashlib
import magic
import os
import uuid as uuid_lib
from flask import Blueprint, request, jsonify, g, current_app, send_file
from werkzeug.utils import secure_filename
from ..extensions import db
from ..models import Assessment, Control, Artifact
from ..auth import require_auth, require_scope
from ..audit import write_audit
from .assessments import _check_org_access

# MIME types that do not have a reliable magic-byte signature and whose
# declared type we therefore accept without content inspection.
# libmagic does not identify these text-based formats precisely.
_SKIP_MAGIC_CHECK: frozenset = frozenset({
    'text/plain',
    'text/csv',
    'application/json',
    'application/xml',
    'text/xml',
})

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

    # Use a UUID-prefixed filename to avoid collisions; sanitise the
    # caller-supplied filename to prevent path-traversal or shell injection.
    safe_name = f'{uuid_lib.uuid4().hex}_{secure_filename(file_storage.filename or "upload")}'
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
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    query = db.session.query(Artifact).filter(Artifact.assessment_id == assessment_id)
    if control_id := request.args.get('control_id'):
        query = query.filter(Artifact.control_id == control_id)
    if art_type := request.args.get('type'):
        query = query.filter(Artifact.type == art_type)
    query = query.order_by(Artifact.created_at.desc())

    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
    except (TypeError, ValueError):
        return jsonify({'error': 'page and per_page must be integers', 'code': 'INVALID_INPUT'}), 400

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        'items': [a.to_dict() for a in items],
        'total': total,
        'page': page,
        'per_page': per_page,
    }), 200


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
    err = _check_org_access(assessment.org_id)
    if err:
        return err
    if assessment.status == 'archived':
        return jsonify({'error': 'Archived assessments are read-only', 'code': 'INVALID_STATE'}), 409

    if 'file' not in request.files:
        return jsonify({'error': 'file field is required', 'code': 'INVALID_INPUT'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected', 'code': 'INVALID_INPUT'}), 400

    # MIME type validation — check the Content-Type header first, then verify
    # that the actual file content matches via magic-byte inspection.
    content_type = (file.content_type or '').split(';')[0].strip().lower()
    if content_type not in ALLOWED_MIME_TYPES:
        return jsonify({
            'error': 'Unsupported file type',
            'code': 'UNSUPPORTED_MEDIA_TYPE',
            'allowed_types': sorted(ALLOWED_MIME_TYPES),
        }), 415

    # Magic-byte check: read the first 512 bytes via python-magic, then seek
    # back to the start.  Skip the check for text-based types that libmagic
    # does not identify precisely.
    if content_type not in _SKIP_MAGIC_CHECK:
        file.stream.seek(0)
        header_bytes = file.stream.read(512)
        file.stream.seek(0)
        detected = magic.from_buffer(header_bytes, mime=True)
        if detected not in ALLOWED_MIME_TYPES:
            return jsonify({
                'error': 'File content does not match declared MIME type',
                'code': 'UNSUPPORTED_MEDIA_TYPE',
            }), 415
        if detected != content_type:
            return jsonify({
                'error': 'Detected file type does not match declared Content-Type',
                'code': 'UNSUPPORTED_MEDIA_TYPE',
            }), 400

    art_type = request.form.get('type', '').strip()
    if art_type not in VALID_TYPES:
        return jsonify({'error': f'type must be one of: {", ".join(sorted(VALID_TYPES))}', 'code': 'INVALID_INPUT'}), 400

    control_id = request.form.get('control_id')
    if control_id:
        control = db.session.get(Control, control_id)
        if control is None or str(control.assessment_id) != str(assessment_id):
            return jsonify({'error': 'Control not found in this assessment', 'code': 'NOT_FOUND'}), 404

    description = request.form.get('description')
    if description is not None and len(description) > 1000:
        return jsonify({'error': 'description must not exceed 1000 characters', 'code': 'INVALID_INPUT'}), 400

    file_path, file_hash, size_bytes, mime_type = _save_file(file, str(assessment_id))

    try:
        artifact = Artifact(
            assessment_id=assessment_id,
            control_id=control_id,
            type=art_type,
            filename=secure_filename(file.filename or 'upload'),
            file_path=file_path,
            hash=file_hash,
            size_bytes=size_bytes,
            mime_type=mime_type,
            description=description,
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
    except Exception:
        # Clean up the orphaned file if the DB write failed
        try:
            os.remove(file_path)
        except OSError:
            current_app.logger.warning('Could not remove orphaned file: %s', file_path)
        raise

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
    assessment = db.session.get(Assessment, artifact.assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err
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
    assessment = db.session.get(Assessment, artifact.assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    if not artifact.file_path or not os.path.isfile(artifact.file_path):
        return jsonify({'error': 'File no longer available', 'code': 'FILE_NOT_FOUND'}), 410

    upload_dir = os.path.realpath(current_app.config['UPLOAD_DIR'])
    real_path = os.path.realpath(artifact.file_path)
    if not real_path.startswith(upload_dir + os.sep) and real_path != upload_dir:
        return jsonify({'error': 'Forbidden', 'code': 'FORBIDDEN'}), 403

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
        real_path,
        mimetype=artifact.mime_type,
        as_attachment=True,
        download_name=secure_filename(artifact.filename or 'download'),
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
    assessment = db.session.get(Assessment, artifact.assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    file_path = artifact.file_path
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

    # Remove the file from disk after the DB commit succeeds.
    # Validate the real path is within the configured upload directory to
    # prevent path-traversal via a tampered file_path stored in the DB.
    if file_path and os.path.isfile(file_path):
        upload_dir = os.path.realpath(current_app.config.get('UPLOAD_DIR', '/app/uploads'))
        real_path = os.path.realpath(file_path)
        if not real_path.startswith(upload_dir + os.sep) and real_path != upload_dir:
            current_app.logger.error(
                'artifact file_path %r is outside UPLOAD_DIR — deletion blocked', file_path
            )
        else:
            try:
                os.remove(real_path)
            except OSError as exc:
                current_app.logger.warning('artifact file could not be removed: %s — %s', real_path, exc)

    return '', 204
