"""sinauth RS256 token verification for nis2compass."""
import base64
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import urllib.request

_log = logging.getLogger(__name__)

_JWKS_CACHE: dict = {}
_JWKS_LOCK = threading.Lock()
_JWKS_EXPIRY: float = 0.0
_JWKS_TTL = 300  # 5 minutes


def _fetch_jwks(sinauth_url: str) -> dict:
    """Fetch JWKS from sinauth, with 5-minute cache."""
    global _JWKS_CACHE, _JWKS_EXPIRY
    now = time.monotonic()
    with _JWKS_LOCK:
        if now < _JWKS_EXPIRY and _JWKS_CACHE:
            return _JWKS_CACHE
        try:
            with urllib.request.urlopen(f'{sinauth_url}/.well-known/jwks.json', timeout=5) as resp:
                data = json.loads(resp.read())
                _JWKS_CACHE = {k['kid']: k for k in data.get('keys', []) if k.get('kty') == 'RSA'}
                _JWKS_EXPIRY = now + _JWKS_TTL
                return _JWKS_CACHE
        except Exception as exc:
            _log.warning('sinauth: failed to fetch JWKS: %s', exc)
            return _JWKS_CACHE  # return stale on error


def _b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _jwk_to_public_key(jwk: dict):
    """Convert a JWK RSA key to a cryptography RSAPublicKey."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend

    n_bytes = _b64url_decode(jwk['n'])
    e_bytes = _b64url_decode(jwk['e'])
    n = int.from_bytes(n_bytes, 'big')
    e = int.from_bytes(e_bytes, 'big')
    return RSAPublicNumbers(e, n).public_key(default_backend())


def verify_sinauth_token(token: str, sinauth_url: str, issuer: str) -> Optional[dict]:
    """
    Verify a sinauth RS256 JWT token.
    Returns the decoded claims dict on success, None on failure.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        if header.get('alg') != 'RS256':
            return None
        kid = header.get('kid')

        jwks = _fetch_jwks(sinauth_url)
        if not jwks:
            return None
        jwk = jwks.get(kid)
        if jwk is None:
            # Refresh and retry once
            with _JWKS_LOCK:
                global _JWKS_EXPIRY
                _JWKS_EXPIRY = 0
            jwks = _fetch_jwks(sinauth_url)
            jwk = jwks.get(kid)
        if jwk is None:
            _log.warning('sinauth: key %r not found in JWKS', kid)
            return None

        public_key = _jwk_to_public_key(jwk)

        import jwt as _jwt
        payload = _jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            options={'verify_aud': False},
        )

        if payload.get('iss') != issuer:
            _log.warning('sinauth: issuer mismatch: %s', payload.get('iss'))
            return None

        return payload

    except Exception as exc:
        _log.debug('sinauth: token verification failed: %s', exc)
        return None


def is_rs256_token(token: str) -> bool:
    """Quick check: does this token have RS256 in its header?"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        header = json.loads(_b64url_decode(parts[0]))
        return header.get('alg') == 'RS256'
    except Exception:
        return False
