import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
)

# Keys whose values are always redacted (case-insensitive match).
_PII_KEYS = frozenset({
    'email', 'contact_email', 'phone', 'phone_number',
    'ssn', 'national_id', 'tax_id', 'iban',
    'first_name', 'last_name', 'full_name',
    'address', 'street', 'postal_code', 'zip_code',
})


def redact_pii(obj):
    """Return a deep copy of *obj* with PII values replaced by '[REDACTED]'.

    - Any dict key in ``_PII_KEYS`` has its value masked.
    - Any string value matching the email regex is masked.
    - Recurses into nested dicts and lists.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in _PII_KEYS:
                out[k] = '[REDACTED]'
            elif isinstance(v, str) and _EMAIL_RE.fullmatch(v):
                out[k] = '[REDACTED]'
            else:
                out[k] = redact_pii(v)
        return out
    if isinstance(obj, list):
        return [redact_pii(item) for item in obj]
    if isinstance(obj, str) and _EMAIL_RE.fullmatch(obj):
        return '[REDACTED]'
    return obj

# Advisory lock ID for serialising audit chain writes. Must not conflict with
# any other pg_advisory_lock usage in this application.
_AUDIT_CHAIN_LOCK_ID = 1_234_567_890


def _compute_chain_hash(
    entry_id: str,
    action: str,
    actor: str,
    resource_type: str,
    resource_id: str | None,
    prev_hash: str | None,
    timestamp: str,
    version: int = 2,
) -> str:
    """
    SHA-256 chain anchor.

    version=2 (current): fields joined with '||' delimiters.
      Formula: SHA-256(id || action || actor || resource_type || resource_id || prev_hash || timestamp)
    version=1 (legacy):  fields joined by bare concatenation — no delimiter.
      Formula: SHA-256(id + action + actor + resource_type + resource_id + prev_hash + timestamp)

    NULL values are represented as the literal string "NULL" in both versions.

    The version parameter corresponds to the hash_version column on AuditLog
    rows so that chain verification can use the correct formula for each entry.
    """
    rid = resource_id if resource_id else 'NULL'
    ph = prev_hash if prev_hash else 'NULL'
    if version == 1:
        raw = f'{entry_id}{action}{actor}{resource_type}{rid}{ph}{timestamp}'
    else:
        raw = f'{entry_id}||{action}||{actor}||{resource_type}||{rid}||{ph}||{timestamp}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _compute_object_fingerprint(obj: dict | None) -> str | None:
    """SHA-256 of the canonical JSON serialisation of the object."""
    if obj is None:
        return None
    canonical = json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _forward_to_citadel(log_entry: dict) -> None:
    """Forward an audit entry to CITADEL's WORM chain. Fire-and-forget — never raises.

    Previously POSTed to f'{citadel_url}/v1/log', a route that does not
    exist anywhere on CITADEL (real routes are all under /api/v1/, see
    citadel/internal/api/server.go) — every call here silently failed. This
    routes through citadel_client.emit_worm(), which hits the real
    POST /api/v1/worm/emit route and matches its request shape exactly
    (citadel/internal/api/handlers/worm.go).
    """
    from . import citadel_client

    payload = {
        'action': log_entry.get('action'),
        'actor': log_entry.get('actor', 'unknown'),
        'resource_type': log_entry.get('resource_type'),
        'resource_id': str(log_entry.get('resource_id', '')) if log_entry.get('resource_id') is not None else None,
        'risk_class': log_entry.get('risk_class', 'INFO'),
        'chain_hash': log_entry.get('chain_hash'),
        'platform': 'nis2compass',
    }
    citadel_client.emit_worm(
        source='nis2compass',
        event_type=log_entry.get('action') or 'audit_event',
        project_id=citadel_client.PROJECT_ID,
        payload=payload,
    )


def write_audit(
    db_session,
    action: str,
    actor: str,
    resource_type: str,
    resource_id=None,
    risk_class: str = 'INFO',
    metadata: dict | None = None,
    obj: dict | None = None,
) -> None:
    """
    Append one entry to audit_log with a valid CITADEL chain hash.

    This function MUST be called inside an active SQLAlchemy session
    (i.e. within a request context where db.session is open).

    The caller is responsible for committing the session after all
    business-logic changes plus the audit entry have been added.

    Uses a PostgreSQL advisory lock (pg_try_advisory_xact_lock) to
    serialise concurrent chain-hash writes within the same transaction.
    """
    from .models import AuditLog

    # Acquire advisory lock so concurrent requests don't race on prev_hash.
    # Lock ID is defined at module level as _AUDIT_CHAIN_LOCK_ID.
    db_session.execute(text(f'SELECT pg_advisory_xact_lock({_AUDIT_CHAIN_LOCK_ID})'))

    # Fetch the most recent chain_hash (within this transaction's snapshot).
    # Order by seq (BIGSERIAL) which is strictly monotonic — unlike UUID ids.
    last = (
        db_session.query(AuditLog.chain_hash)
        .order_by(AuditLog.seq.desc())
        .first()
    )
    prev_hash = last[0] if last else None

    entry_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    ts = now.isoformat()

    chain_hash = _compute_chain_hash(
        str(entry_id),
        action,
        actor,
        resource_type,
        str(resource_id) if resource_id else None,
        prev_hash,
        ts,
        version=2,
    )

    entry = AuditLog(
        id=entry_id,
        action=action,
        actor=actor,
        resource_type=resource_type,
        resource_id=resource_id,
        risk_class=risk_class,
        metadata_=redact_pii(metadata) if metadata else {},
        object_fingerprint=_compute_object_fingerprint(obj),
        prev_hash=prev_hash,
        chain_hash=chain_hash,
        hash_version=2,
        timestamp=now,
    )
    db_session.add(entry)

    # Fire-and-forget webhook delivery — deferred until after commit so that
    # the webhook is only sent for writes that actually persisted.
    try:
        from flask import current_app
        webhook_url = current_app.config.get('WEBHOOK_URL', '')
        webhook_secret = current_app.config.get('WEBHOOK_SECRET', '')
        if webhook_url:
            from .webhook import dispatch
            entry_dict = entry.to_dict()

            from sqlalchemy import event as sa_event

            def _after_commit(session):
                dispatch(entry_dict, webhook_url, webhook_secret)
                sa_event.remove(session, 'after_commit', _after_commit)
                sa_event.remove(session, 'after_rollback', _after_rollback)

            def _after_rollback(session):
                sa_event.remove(session, 'after_commit', _after_commit)
                sa_event.remove(session, 'after_rollback', _after_rollback)

            sa_event.listen(db_session, 'after_commit', _after_commit)
            sa_event.listen(db_session, 'after_rollback', _after_rollback)
    except RuntimeError:
        pass  # No app context (e.g. during testing without full stack)

    # Forward to CITADEL (fire-and-forget — never raises) — deferred until
    # after commit so that a rolled-back transaction does not send a ghost
    # event to CITADEL.
    try:
        from flask import current_app as _app
        from sqlalchemy import event as sa_event

        citadel_url = _app.config.get('CITADEL_API_URL')
        if citadel_url:
            entry_data = {
                'action': action,
                'actor': actor,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'risk_class': risk_class,
                'chain_hash': chain_hash,
            }

            def _after_commit_citadel(session):
                _forward_to_citadel(entry_data)
                sa_event.remove(session, 'after_commit', _after_commit_citadel)
                sa_event.remove(session, 'after_rollback', _after_rollback_citadel)

            def _after_rollback_citadel(session):
                sa_event.remove(session, 'after_commit', _after_commit_citadel)
                sa_event.remove(session, 'after_rollback', _after_rollback_citadel)

            sa_event.listen(db_session, 'after_commit', _after_commit_citadel)
            sa_event.listen(db_session, 'after_rollback', _after_rollback_citadel)
    except RuntimeError:
        pass  # No app context (e.g. during testing without full stack)
