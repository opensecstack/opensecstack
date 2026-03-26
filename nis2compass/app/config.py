import ipaddress
import logging
import os
import urllib.parse

_logger = logging.getLogger(__name__)


def _build_database_uri() -> str:
    """Return the database URI, failing fast if credentials are not configured."""
    db_url = os.getenv('NIS2_DB_URL')
    if db_url:
        return db_url

    db_password = os.getenv('NIS2_DB_PASSWORD') or None
    if not db_password:
        _logger.warning(
            'NIS2_DB_PASSWORD not set — refusing to start with default credentials'
        )
        raise RuntimeError(
            'NIS2_DB_PASSWORD (or NIS2_DB_URL) must be set; '
            'refusing to start with no database password.'
        )

    db_user = os.getenv('NIS2_DB_USER', 'nis2compass')
    db_host = os.getenv('NIS2_DB_HOST', 'localhost')
    db_port = os.getenv('NIS2_DB_PORT', '5432')
    db_name = os.getenv('NIS2_DB_NAME', 'nis2compass')
    encoded_password = urllib.parse.quote_plus(db_password)
    return (
        f"postgresql+psycopg2://{db_user}:{encoded_password}"
        f"@{db_host}:{db_port}/{db_name}"
    )


class Config:
    # ------------------------------------------------------------------ #
    # Database                                                             #
    # ------------------------------------------------------------------ #
    SQLALCHEMY_DATABASE_URI = _build_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.getenv('NIS2_DB_POOL_SIZE', '10')),
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # ------------------------------------------------------------------ #
    # Redis                                                                #
    # ------------------------------------------------------------------ #
    REDIS_URL = os.getenv('NIS2_REDIS_URL', 'redis://localhost:6379/0')

    # ------------------------------------------------------------------ #
    # JWT / auth                                                           #
    # ------------------------------------------------------------------ #
    JWT_SECRET = os.getenv('NIS2_JWT_SECRET', '')
    JWT_TTL = int(os.getenv('NIS2_JWT_TTL', '3600'))

    # Comma-separated list of accepted plaintext API keys.
    # In production, generate with: openssl rand -hex 32
    API_KEYS = [
        k.strip()
        for k in os.getenv('NIS2_API_KEYS', '').split(',')
        if k.strip()
    ]

    # ------------------------------------------------------------------ #
    # Flask                                                                #
    # ------------------------------------------------------------------ #
    SECRET_KEY = os.getenv('NIS2_SECRET_KEY', 'dev-secret-key-do-not-use-in-production')
    DEBUG = os.getenv('NIS2_DEBUG', 'false').lower() == 'true'
    WEBHOOK_URL = os.getenv('NIS2_WEBHOOK_URL', '')           # POST target; empty = disabled
    WEBHOOK_SECRET = os.getenv('NIS2_WEBHOOK_SECRET', '')     # HMAC-SHA256 signing secret

    # H1: require WEBHOOK_SECRET when WEBHOOK_URL is configured — signing with
    # an empty secret provides no authentication for the webhook receiver.
    if WEBHOOK_URL and not WEBHOOK_SECRET:
        raise ValueError(
            'NIS2_WEBHOOK_SECRET must be set when NIS2_WEBHOOK_URL is configured. '
            'Generate one with: openssl rand -hex 32'
        )

    # validate WEBHOOK_URL at startup — reject non-http(s), localhost, and
    # private-range addresses to prevent Server-Side Request Forgery (SSRF).
    if WEBHOOK_URL:
        _parsed = urllib.parse.urlparse(WEBHOOK_URL)
        if _parsed.scheme not in ('http', 'https'):
            raise ValueError(
                f'NIS2_WEBHOOK_URL has an invalid scheme {_parsed.scheme!r}; '
                'only http and https are permitted.'
            )
        _hostname = _parsed.hostname or ''
        _BLOCKED_HOSTNAMES = {'localhost', '127.0.0.1', '::1'}
        if _hostname in _BLOCKED_HOSTNAMES:
            raise ValueError(
                f'NIS2_WEBHOOK_URL hostname {_hostname!r} is not allowed (loopback).'
            )
        try:
            _addr = ipaddress.ip_address(_hostname)
            if _addr.is_private or _addr.is_loopback or _addr.is_link_local:
                raise ValueError(
                    f'NIS2_WEBHOOK_URL resolves to a private/loopback address '
                    f'{_hostname!r}, which is not permitted.'
                )
        except ValueError as _exc:
            # Re-raise if it came from our own check above (contains 'NIS2_WEBHOOK_URL')
            if 'NIS2_WEBHOOK_URL' in str(_exc):
                raise
            # Otherwise _hostname is a DNS name, not a bare IP — that is acceptable.
    ENV = os.getenv('NIS2_ENV', 'production')
    CORS_ORIGINS = os.getenv('NIS2_CORS_ORIGINS', '*').split(',') if os.getenv('NIS2_CORS_ORIGINS') else (
        ['*'] if os.getenv('NIS2_ENV', 'production') == 'development' else []
    )

    # ------------------------------------------------------------------ #
    # Rate limiting                                                        #
    # ------------------------------------------------------------------ #
    RATE_LIMIT = int(os.getenv('NIS2_RATE_LIMIT', '100'))  # requests / minute / IP

    # Comma-separated list of trusted upstream proxy IPs.
    # X-Forwarded-For is only honoured when the connection comes from one of
    # these addresses.  Leave empty to use the direct connection IP only.
    TRUSTED_PROXIES = os.getenv('NIS2_TRUSTED_PROXIES', '')

    # ------------------------------------------------------------------ #
    # File uploads                                                         #
    # ------------------------------------------------------------------ #
    MAX_CONTENT_LENGTH = int(os.getenv('NIS2_MAX_UPLOAD_BYTES', str(20 * 1024 * 1024)))
    UPLOAD_DIR = os.getenv('NIS2_UPLOAD_DIR', '/app/uploads')

    # ------------------------------------------------------------------ #
    # CITADEL audit forwarding (optional)                                  #
    # ------------------------------------------------------------------ #
    CITADEL_API_URL = os.environ.get('CITADEL_API_URL', '')
    CITADEL_API_KEY = os.environ.get('CITADEL_API_KEY', '')
