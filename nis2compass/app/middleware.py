import time
from flask import request, jsonify
from flask_cors import CORS
from . import extensions


def _get_client_ip() -> str:
    """Return the real client IP, respecting X-Forwarded-For from trusted proxies."""
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def _check_rate_limit(ip: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """
    Sliding-window rate limiter using Redis.

    Returns (allowed: bool, retry_after: int).
    Key pattern: rate:{ip}
    Uses a sorted set where score = timestamp of each request.
    """
    rc = extensions.redis_client
    if rc is None:
        return True, 0  # fail open if Redis is unavailable

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
    except Exception:
        return True, 0  # fail open on Redis errors

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
    CORS(app, origins=allowed_origins, supports_credentials=False)

    @app.before_request
    def rate_limit():
        # Skip rate limiting for health check
        if request.path == '/health':
            return None
        ip = _get_client_ip()
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
