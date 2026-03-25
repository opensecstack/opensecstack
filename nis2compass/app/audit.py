import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import text


def _compute_chain_hash(
    entry_id: str,
    action: str,
    actor: str,
    resource_type: str,
    resource_id: str | None,
    prev_hash: str | None,
    timestamp: str,
) -> str:
    """
    SHA-256 chain anchor.
    Formula: SHA-256(id || action || actor || resource_type || resource_id || prev_hash || timestamp)
    NULL values are represented as the literal string "NULL".
    """
    rid = resource_id if resource_id else 'NULL'
    ph = prev_hash if prev_hash else 'NULL'
    raw = f'{entry_id}{action}{actor}{resource_type}{rid}{ph}{timestamp}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _compute_object_fingerprint(obj: dict | None) -> str | None:
    """SHA-256 of the canonical JSON serialisation of the object."""
    if obj is None:
        return None
    canonical = json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _forward_to_citadel(log_entry: dict) -> None:
    """Forward an audit entry to CITADEL HTTP API. Fire-and-forget — never raises."""
    try:
        from flask import current_app
        citadel_url = current_app.config.get('CITADEL_API_URL')
    except RuntimeError:
        return  # No app context (e.g. during testing without full stack)
    if not citadel_url:
        return
    try:
        import requests  # lazy import — only used if CITADEL is configured
        payload = {
            'action_type': log_entry.get('action'),
            'actor_user_id': log_entry.get('actor', 'unknown'),
            'actor_role': 'NIS2_COMPASS',
            'result_status': 'EXECUTED',
            'system_module': 'nis2compass',
            'resource_id': str(log_entry.get('resource_id', '')),
            'data_hash': log_entry.get('chain_hash'),
            'metadata': {
                'resource_type': log_entry.get('resource_type'),
                'risk_class': log_entry.get('risk_class', 'INFO'),
                'platform': 'nis2compass',
            }
        }
        try:
            from flask import current_app as _app
            api_key = _app.config.get('CITADEL_API_KEY')
        except RuntimeError:
            api_key = None
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        requests.post(
            f'{citadel_url.rstrip("/")}/v1/log',
            json=payload,
            headers=headers,
            timeout=2.0,
        )
    except Exception:
        pass  # CITADEL forwarding is best-effort


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
    # Lock ID is arbitrary but fixed — all writers contend on the same key.
    AUDIT_LOCK_ID = 1_234_567_890
    db_session.execute(text(f'SELECT pg_advisory_xact_lock({AUDIT_LOCK_ID})'))

    # Fetch the most recent chain_hash (within this transaction's snapshot).
    last = (
        db_session.query(AuditLog.chain_hash)
        .order_by(AuditLog.timestamp.desc())
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
    )

    entry = AuditLog(
        id=entry_id,
        action=action,
        actor=actor,
        resource_type=resource_type,
        resource_id=resource_id,
        risk_class=risk_class,
        metadata_=metadata or {},
        object_fingerprint=_compute_object_fingerprint(obj),
        prev_hash=prev_hash,
        chain_hash=chain_hash,
        timestamp=now,
    )
    db_session.add(entry)

    # Fire-and-forget webhook delivery (does not block the request)
    try:
        from flask import current_app
        webhook_url = current_app.config.get('WEBHOOK_URL', '')
        webhook_secret = current_app.config.get('WEBHOOK_SECRET', '')
        if webhook_url:
            from .webhook import dispatch
            dispatch(entry.to_dict(), webhook_url, webhook_secret)
    except RuntimeError:
        pass  # No app context (e.g. during testing without full stack)

    # Forward to CITADEL (fire-and-forget — never raises)
    entry_data = {
        'action': action,
        'actor': actor,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'risk_class': risk_class,
        'chain_hash': chain_hash,
    }
    _forward_to_citadel(entry_data)
