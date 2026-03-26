import logging
import time
import uuid as _uuid_mod
from flask import request, jsonify
from flask_cors import CORS
from . import extensions

_log = logging.getLogger(__name__)

# Lua script for atomic sliding-window rate-limit check-and-add.
# Eliminates the TOCTOU race where two concurrent requests both observe
# count < limit and both get admitted.
# KEYS[1] = Redis key
# ARGV[1] = now in milliseconds (used as score)
# ARGV[2] = window size in milliseconds
# ARGV[3] = limit (max requests per window)
# ARGV[4] = unique request identifier (member in the sorted set)
# Returns: {1, new_count} if allowed; {0, current_count} if denied.
LUA_RATE_LIMIT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local req_id = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
    return {0, count}
end
redis.call('ZADD', key, now, req_id)
redis.call('EXPIRE', key, math.ceil(window / 1000))
return {1, count + 1}
"""

# Registered once per Redis connection; reset to None when Redis reconnects.
_rate_limit_script = None


def _get_rate_limit_script(rc):
    """Return the registered Lua script, registering it on first call."""
    global _rate_limit_script
    if _rate_limit_script is None:
        _rate_limit_script = rc.register_script(LUA_RATE_LIMIT)
    return _rate_limit_script


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
    Sliding-window rate limiter using Redis with an atomic Lua script.

    Returns (allowed: bool, retry_after: int).
    Key pattern: rate:{ip}
    Uses a sorted set where score = timestamp (ms) of each request.
    The Lua script performs the check-and-add atomically to prevent TOCTOU
    races under concurrent load.
    """
    rc = extensions.redis_client
    if rc is None:
        _log.warning('rate_limit: Redis unavailable — rate limiting disabled')
        return True, 0

    # Use milliseconds as the score so the window arithmetic inside Lua is
    # consistent with the EXPIRE call (which takes seconds).
    now_ms = time.time() * 1000
    window_ms = window * 1000
    key = f'rate:{ip}'
    req_id = str(_uuid_mod.uuid4())

    try:
        script = _get_rate_limit_script(rc)
        result = script(keys=[key], args=[now_ms, window_ms, limit, req_id])
        allowed = int(result[0]) == 1
    except Exception as exc:
        _log.warning('rate_limit: Redis error, failing open: %s', exc)
        return True, 0

    if not allowed:
        # Estimate retry_after from the oldest entry still in the window.
        try:
            oldest_score = rc.zrange(key, 0, 0, withscores=True)
            if oldest_score:
                oldest_ms = oldest_score[0][1]
                retry_after = int((oldest_ms + window_ms - now_ms) / 1000) + 1
            else:
                retry_after = window
        except Exception:
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
