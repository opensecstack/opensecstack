"""Minimal CITADEL client for NIS2 Compass.

There is no shared Python SDK equivalent to sdk/go/citadel yet, so this
module is nis2compass's own client, scoped to what nis2compass needs. It
implements the three CITADEL HTTP contracts used by this platform:

  - POST /api/v1/worm/emit        — plain audit-log append, no authorization
    decision. Fire-and-forget (never raises into the caller).
  - POST /api/v1/marshal/evaluate — MARSHAL governance decision (5 gates:
    AuthN -> AuthZ -> NDS -> AUGUR -> WORM). Synchronous; callers that use
    this for a governance-candidate action MUST honour a REFUSE/HARD_STOP
    outcome by blocking the action (see evaluate_governance_action below).
  - POST /api/v1/evidence/submit  — Compliance Evidence push (root
    CLAUDE.md's SDK-contract table, "Compliance Evidence | JSON v1"). Not a
    governance decision (nothing to REFUSE/HARD_STOP — the caller isn't
    asking permission), so it does not go through MARSHAL; instead it lands
    as a retrievable, structured record on CITADEL's side, tamper-evidenced
    via CITADEL's own WORM chain forwarding (see
    citadel/internal/api/handlers/evidence.go). Best-effort like emit_worm,
    not fail-closed like evaluate — see submit_compliance_evidence below for
    why.

Wire shapes mirror citadel/internal/marshal/types.go,
citadel/internal/api/handlers/worm.go, and
citadel/internal/api/handlers/evidence.go exactly (field names, nesting,
`omitempty` semantics) — that Go source is the contract of record. Field
names below were copied 1:1 from the Go struct tags, not guessed. The
Compliance Evidence wire shape additionally matches
sdk/go/opensecstack.SubmitComplianceEvidenceRequest field-for-field (see
that type's doc comment for the same "Go source is the contract of record"
convention, applied to a non-Kerkese contract).

Kerkese field/value conventions (project_id="nis2compass",
kerkese_version="1.0", Actor/Verifier.Role as free-form producer-asserted
strings) match the one other real producer wired up in this monorepo,
apiguard (apiguard/internal/api/handlers/scans.go) — see that file for the
precedent this module follows.
"""

import logging
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)

# Matches the literal string apiguard/sdk/go/citadel fixtures use for
# Kerkese.KerkeseVersion ("1.0") — the "CITADEL Kerkese | JSON v2.0" row in
# the ecosystem SDK-contract table (root CLAUDE.md) describes the *schema's*
# version, not this per-request field's value.
KERKESE_VERSION = "1.0"

# Kerkese.ProjectID — a stable per-platform identifier, matching how
# apiguard sets ProjectID to its own platform name (see
# apiguard/internal/citadel/client_test.go / sdk/go/citadel/sign_test.go
# fixtures using ProjectID: "apiguard").
PROJECT_ID = "nis2compass"

# Placeholder Verifier identity used when NIS2 Compass has no real
# second-approver for a governance action. Distinct from any real sinauth
# user id so it can never accidentally collide with Actor.UserID and trip
# Gate 3's NDS_SAME_IDENTITY hard-stop. Role is deliberately the lowest
# privilege group (roleGroup("viewer") == "standard" in CITADEL) since this
# identity does not correspond to a real approver — see
# citadel/adrs/005-sinauth-identity-bridge.md's apiguard-system-verifier
# precedent for the same pattern.
SYSTEM_VERIFIER_USER_ID = "nis2compass-system-verifier"
SYSTEM_VERIFIER_ROLE = "viewer"


class CitadelUnavailableError(Exception):
    """CITADEL could not be reached, or returned a response evaluate() cannot parse.

    Callers evaluating a governance-candidate action MUST treat this the
    same as a blocking decision (fail-closed) — see
    evaluate_governance_action. emit_worm() never raises this; it only logs.
    """


class CitadelNotConfiguredError(CitadelUnavailableError):
    """CITADEL_API_URL is not set for this deployment.

    Distinct from a configured-but-unreachable CITADEL (a real infra
    failure, which evaluate_governance_action fails closed on): a
    deployment that has not opted into CITADEL integration at all is not
    "governance failed", it's "governance is off" — matching emit_worm's
    existing no-op behaviour when CITADEL isn't configured, and keeping
    every pre-existing nis2compass test/deployment that doesn't set
    CITADEL_API_URL working exactly as before this integration was added.
    """


class CitadelGovernanceError(Exception):
    """Raised when MARSHAL returns REFUSE or HARD_STOP for a governance-candidate action."""

    def __init__(self, decision: dict):
        self.decision = decision
        self.outcome = decision.get("outcome")
        self.reasons = decision.get("reasons") or []
        super().__init__(f"CITADEL {self.outcome}: {'; '.join(self.reasons) or 'no reason given'}")


def _citadel_config() -> tuple[str | None, str | None]:
    """Return (citadel_url, api_key) from the current Flask app config.

    Raises RuntimeError if there is no active app context (propagated to
    callers so emit_worm can swallow it and evaluate can surface it).
    """
    from flask import current_app

    url = current_app.config.get("CITADEL_API_URL")
    api_key = current_app.config.get("CITADEL_API_KEY")
    return url, api_key


def emit_worm(source: str, event_type: str, project_id: str, payload: dict | None) -> None:
    """POST /api/v1/worm/emit — plain audit append, no authorization decision.

    Fire-and-forget, matching the existing _forward_to_citadel behaviour in
    app/audit.py: logs a warning on any failure, never raises into the
    caller's request.
    """
    try:
        url, api_key = _citadel_config()
    except RuntimeError:
        return  # no app context (e.g. tests without full stack)
    if not url:
        return

    try:
        import requests  # lazy import — only used if CITADEL is configured

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        requests.post(
            f'{url.rstrip("/")}/api/v1/worm/emit',
            json={
                "source": source,
                "event_type": event_type,
                "project_id": project_id or "",
                "payload": payload or {},
            },
            headers=headers,
            timeout=2.0,
        )
    except Exception as exc:
        try:
            from flask import current_app

            current_app.logger.warning("CITADEL worm/emit failed: %s", exc)
        except RuntimeError:
            pass


def submit_compliance_evidence(
    organisation_id: str,
    assessment_id: str,
    report: bytes,
    *,
    actor_token: str,
    schema_version: str = "1.0",
    timeout: float = 5.0,
) -> dict | None:
    """POST /api/v1/evidence/submit — push a generated compliance report to CITADEL.

    Wire shape matches citadel/internal/api/handlers/evidence.go's
    submitEvidenceRequest and sdk/go/opensecstack.SubmitComplianceEvidenceRequest
    field-for-field (see this module's docstring).

    Error-handling philosophy: best-effort, matching emit_worm rather than
    evaluate_governance_action. This is a deliberate choice, not an
    oversight — unlike a governance-candidate action (where CITADEL being
    unreachable must block the action, since it might have said REFUSE),
    compliance evidence submission has no verdict to honour. The
    report was already generated and, in the caller's actual use (see
    app/api/assessments.py's generate_report), is already being returned to
    the requesting user as a download. Making that download fail — or
    making the HTTP request hang for `timeout` seconds — because CITADEL
    happens to be down would turn an availability problem in an optional
    audit-forwarding path into an availability problem in the primary
    compliance-reporting feature, which is the wrong trade-off for a
    "deposit a copy in the audit trail" side effect. On any failure this
    logs a warning and returns None; it never raises into the caller.

    Returns the parsed response dict (`id`, `worm_entry_id`, `chain_hash`,
    `submitted_at`) on HTTP 201, or None if CITADEL is not configured, the
    request fails, or the response cannot be parsed as the expected shape.
    Callers that want to record "this assessment's evidence was submitted
    to CITADEL at time T with reference R" should treat None as "not
    submitted this attempt" and simply leave the previous reference (if
    any) in place rather than erroring the request.
    """
    try:
        url, api_key = _citadel_config()
    except RuntimeError:
        return None  # no app context (e.g. tests without full stack)
    if not url:
        return None

    try:
        import requests  # lazy import — only used if CITADEL is configured

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # `report` is already-serialised JSON bytes (see
        # app/reporters/json_reporter.py's generate_json_report) — decode it
        # back into an object so it nests as real JSON under the "report"
        # key of the request body, matching submitEvidenceRequest.Report
        # (json.RawMessage on the Go side), rather than double-encoding it
        # as an escaped JSON string.
        import json as _json

        report_obj = _json.loads(report.decode("utf-8"))

        resp = requests.post(
            f'{url.rstrip("/")}/api/v1/evidence/submit',
            json={
                "actor_token": actor_token,
                "organisation_id": organisation_id,
                "assessment_id": assessment_id,
                "schema_version": schema_version,
                "report": report_obj,
            },
            headers=headers,
            timeout=timeout,
        )
    except Exception as exc:
        try:
            from flask import current_app

            current_app.logger.warning("CITADEL evidence/submit failed: %s", exc)
        except RuntimeError:
            pass
        return None

    if resp.status_code != 201:
        try:
            from flask import current_app

            current_app.logger.warning(
                "CITADEL evidence/submit returned unexpected HTTP %s: %s", resp.status_code, resp.text
            )
        except RuntimeError:
            pass
        return None

    try:
        return resp.json()
    except ValueError as exc:
        try:
            from flask import current_app

            current_app.logger.warning("CITADEL evidence/submit returned a non-JSON response: %s", exc)
        except RuntimeError:
            pass
        return None


def build_kerkese(
    action_type: str,
    *,
    actor_user_id: str,
    actor_role: str,
    actor_token: str = "",
    actor_email: str | None = None,
    verifier_user_id: str = SYSTEM_VERIFIER_USER_ID,
    verifier_role: str = SYSTEM_VERIFIER_ROLE,
    verifier_token: str = "",
    verifier_email: str | None = None,
    description: str = "",
    change_id: str = "",
) -> dict:
    """Build a Kerkese dict matching citadel/internal/marshal/types.go.

    Field names/nesting below are a direct 1:1 mapping of the Go struct's
    json tags — see the module docstring.
    """
    now = datetime.now(timezone.utc)
    kerkese: dict[str, Any] = {
        "kerkese_version": KERKESE_VERSION,
        "ts_utc": now.isoformat(),
        "project_id": PROJECT_ID,
        "execution_id": str(_uuid.uuid4()),
        "action": {
            "type": action_type,
            "description": description,
            "change_id": change_id,
        },
        "actor": {
            "user_id": actor_user_id,
            "role": actor_role,
        },
        "verifier": {
            "user_id": verifier_user_id,
            "role": verifier_role,
        },
        "evidence": {},
        "sod": {
            "operator_user_id": actor_user_id,
            "verifier_user_id": verifier_user_id,
        },
        "dry_run": False,
        "actor_token": actor_token,
        "verifier_token": verifier_token,
    }
    if actor_email:
        kerkese["actor"]["email"] = actor_email
    if verifier_email:
        kerkese["verifier"]["email"] = verifier_email
    return kerkese


def evaluate(kerkese: dict, *, timeout: float = 5.0) -> dict:
    """POST /api/v1/marshal/evaluate. Synchronous.

    Returns the parsed Decision dict (`outcome`, `gates`, `reasons`,
    `worm_entry_id`, ...) on any response CITADEL considers a real
    decision (HTTP 200 EXECUTE, or HTTP 403 REFUSE/HARD_STOP — MARSHAL's
    handler writes the full Decision body on both).

    Raises CitadelUnavailableError if CITADEL is unreachable, misconfigured,
    or returns something that is not a Decision (network error, non-JSON
    body, 4xx/5xx that isn't the 403-with-Decision case). Callers
    evaluating a governance-candidate action must treat this the same as a
    blocking outcome — see evaluate_governance_action.
    """
    url, api_key = _citadel_config()
    if not url:
        raise CitadelNotConfiguredError("CITADEL_API_URL is not configured")

    import requests

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        resp = requests.post(
            f'{url.rstrip("/")}/api/v1/marshal/evaluate',
            json=kerkese,
            headers=headers,
            timeout=timeout,
        )
    except Exception as exc:
        raise CitadelUnavailableError(f"CITADEL marshal/evaluate request failed: {exc}") from exc

    try:
        decision: dict = resp.json()
    except ValueError as exc:
        raise CitadelUnavailableError(f"CITADEL returned a non-JSON response (HTTP {resp.status_code}): {exc}") from exc

    if resp.status_code not in (200, 403):
        raise CitadelUnavailableError(f"CITADEL returned unexpected HTTP {resp.status_code}: {decision}")
    if "outcome" not in decision:
        raise CitadelUnavailableError(f'CITADEL response missing "outcome": {decision}')

    return decision


def evaluate_governance_action(
    action_type: str,
    *,
    actor_user_id: str,
    actor_role: str,
    actor_token: str = "",
    actor_email: str | None = None,
    verifier_user_id: str = SYSTEM_VERIFIER_USER_ID,
    verifier_role: str = SYSTEM_VERIFIER_ROLE,
    verifier_token: str = "",
    verifier_email: str | None = None,
    description: str = "",
    change_id: str = "",
) -> dict:
    """Build + submit a Kerkese for a governance-candidate action and enforce the verdict.

    Synchronous by design (unlike emit_worm). Returns the Decision dict on
    EXECUTE. Raises CitadelGovernanceError on REFUSE/HARD_STOP.

    If CITADEL_API_URL is not configured at all, governance is treated as
    disabled for this deployment (same no-op philosophy as emit_worm) and
    the action is allowed to proceed — a synthetic EXECUTE decision is
    returned. If CITADEL *is* configured but cannot actually be reached
    (network failure, malformed response, 5xx), that is a real
    infrastructure failure and CitadelUnavailableError propagates — callers
    MUST treat that as blocking (fail-closed): a governance action whose
    authorization decision cannot be obtained from a supposedly-live
    CITADEL must not be allowed to proceed un-governed. Route handlers
    should catch both CitadelGovernanceError and CitadelUnavailableError
    and return an error response instead of committing.
    """
    kerkese = build_kerkese(
        action_type,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        actor_token=actor_token,
        actor_email=actor_email,
        verifier_user_id=verifier_user_id,
        verifier_role=verifier_role,
        verifier_token=verifier_token,
        verifier_email=verifier_email,
        description=description,
        change_id=change_id,
    )
    try:
        decision = evaluate(kerkese)
    except CitadelNotConfiguredError:
        return {
            "outcome": "EXECUTE",
            "gates": [],
            "reasons": ["CITADEL_NOT_CONFIGURED: governance skipped, no CITADEL_API_URL set"],
        }
    outcome = decision.get("outcome")
    if outcome in ("REFUSE", "HARD_STOP"):
        raise CitadelGovernanceError(decision)
    return decision


def current_actor_identity() -> dict:
    """Pull the real authenticated identity for the current Flask request.

    Sourced from app.auth.require_auth, which sets g.actor (sinauth `sub`
    when the request carries a real sinauth RS256 token, otherwise the
    legacy JWT's `sub`), g.token_role, g.actor_email, and g.raw_token (the
    raw bearer string — forwarded as Kerkese.ActorToken so CITADEL can
    verify it against sinauth's JWKS itself).

    Must be called within an authenticated request (i.e. after
    @require_auth has run) — raises RuntimeError otherwise, since a
    governance evaluation with no real actor identity would be meaningless.
    """
    from flask import g

    actor_user_id = getattr(g, "actor", None)
    if not actor_user_id:
        raise RuntimeError("current_actor_identity() called outside an authenticated request")
    return {
        "actor_user_id": actor_user_id,
        "actor_role": getattr(g, "token_role", "viewer"),
        "actor_token": getattr(g, "raw_token", "") or "",
        "actor_email": getattr(g, "actor_email", None),
    }
