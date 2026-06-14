"""HS256 JWT verification for the FastAPI service.

Mirrors the cyberpath / openscrub auth pattern: shared secret with the
Go core, ``Authorization: Bearer <jwt>`` header, claims surfaced via a
FastAPI dependency. Dev mode (no secret configured) admits requests
with a synthetic anonymous claim — explicit, not silent.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from advisory.config import Settings, get_settings

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Claims:
    """Subset of JWT claims the service inspects."""

    sub: str
    role: str
    issuer: str = ""


def _decode(token: str, secret: str, issuer: str) -> Claims:
    """Verify and decode an HS256 token."""
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp"]},
            issuer=issuer or None,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_token", "message": str(exc)},
        ) from exc
    return Claims(
        sub=str(payload.get("sub", "")),
        role=str(payload.get("role", "")),
        issuer=str(payload.get("iss", "")),
    )


def require_auth(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
) -> Claims:
    """FastAPI dependency that returns Claims or raises 401.

    Dev mode (no secret + dev_mode=True OR no secret at all) injects a
    synthetic ``dev-anonymous`` admin claim so local development works
    without minting a JWT. Production deployments MUST set
    ``OPENCSIRT_PY_JWT_SECRET`` — the middleware fails closed otherwise.
    """
    settings = settings or get_settings()
    if not settings.jwt_secret:
        if settings.dev_mode:
            return Claims(sub="dev-anonymous", role="admin", issuer=settings.jwt_issuer)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "auth_misconfigured",
                "message": "OPENCSIRT_PY_JWT_SECRET is not set",
            },
        )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "missing_token", "message": "Bearer token required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = _decode(credentials.credentials, settings.jwt_secret, settings.jwt_issuer)
    request.state.claims = claims
    return claims


def require_role(*roles: str) -> Callable[[Claims], Claims]:
    """Higher-order dependency that enforces RBAC on top of require_auth."""

    def _dep(claims: Annotated[Claims, Depends(require_auth)]) -> Claims:
        if roles and claims.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "forbidden", "message": "insufficient role"},
            )
        return claims

    return _dep
