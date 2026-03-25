import logging
import time
from flask import request, jsonify
from flask_cors import CORS
from . import extensions

_log = logging.getLogger(__name__)


def _get_client_ip(trusted_proxies: set) -> str:
    """Return the real client IP.

    X-Forwarded-For is only trusted when the immediate connection comes from
    a configured trusted proxy.  Without a proxy allowlist the header is
    trivially spoofable and must be ignored.
    """
    remote = request.remote_addr or '0.0.0.0'
    if trusted_proxies and remote in trusted_proxies:
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            return xff.split(',')[0].strip()
    return remote


def _check_rate_limit(ip: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """
    Sliding-window rate limiter using Redis.

    Returns (allowed: bool, retry_after: int).
    Key pattern: rate:{ip}
    Uses a sorted set where score = timestamp of each request.
    """
    rc = extensions.redis_client
    if rc is None:
        _log.warning('rate_limit: Redis unavailable — rate limiting disabled')
        return True, 0

    now = time.time()
    key = f'rate:{ip}'
    pipe = rc.pipeline()
    # Remove entries outside the current window
    pipe.zremrangebyscore(key, 0, now - window)
    # Count remaining entries
    pipe.zcard(key)
    # Add current request
    pipe.zadd(key, {str(now): now})
    # Expire the key after the window to clean up idle IPs
    pipe.expire(key, window * 2)
    try:
        results = pipe.execute()
        count = results[1]
    except Exception as exc:
        _log.warning('rate_limit: Redis error, failing open: %s', exc)
        return True, 0

    if count >= limit:
        oldest_score = rc.zrange(key, 0, 0, withscores=True)
        if oldest_score:
            retry_after = int(window - (now - oldest_score[0][1])) + 1
        else:
            retry_after = window
        return False, retry_after

    return True, 0


def apply_middleware(app) -> None:
    """Register before/after request hooks on the Flask app."""

    # CORS — restrict to configured origins in production
    allowed_origins = app.config.get('CORS_ORIGINS', '*' if app.debug else [])
    if not allowed_origins and not app.debug:
        _log.warning(
            'CORS_ORIGINS is empty — cross-origin requests from the web frontend '
            'will be blocked. Set NIS2_CORS_ORIGINS to a comma-separated list of '
            'allowed origins (e.g. https://nis2.example.com).'
        )
    CORS(app, origins=allowed_origins, supports_credentials=False)

    @app.before_request
    def rate_limit():
        # Skip rate limiting for health check
        if request.path == '/health':
            return None
        trusted = set(
            p.strip()
            for p in app.config.get('TRUSTED_PROXIES', '').split(',')
            if p.strip()
        )
        ip = _get_client_ip(trusted)
        limit = app.config.get('RATE_LIMIT', 100)
        allowed, retry_after = _check_rate_limit(ip, limit)
        if not allowed:
            response = jsonify({'error': 'Rate limit exceeded', 'code': 'RATE_LIMITED'})
            response.status_code = 429
            response.headers['Retry-After'] = str(retry_after)
            return response
        return None

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'none'"
        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
        return response
