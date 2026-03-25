import os


class Config:
    # ------------------------------------------------------------------ #
    # Database                                                             #
    # ------------------------------------------------------------------ #
    SQLALCHEMY_DATABASE_URI = os.getenv('NIS2_DB_URL') or (
        "postgresql+psycopg2://"
        f"{os.getenv('NIS2_DB_USER', 'nis2compass')}:"
        f"{os.getenv('NIS2_DB_PASSWORD', 'nis2compassdev')}@"
        f"{os.getenv('NIS2_DB_HOST', 'localhost')}:"
        f"{os.getenv('NIS2_DB_PORT', '5432')}/"
        f"{os.getenv('NIS2_DB_NAME', 'nis2compass')}"
    )
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
