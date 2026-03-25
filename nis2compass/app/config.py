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
    ENV = os.getenv('NIS2_ENV', 'production')

    # ------------------------------------------------------------------ #
    # Rate limiting                                                        #
    # ------------------------------------------------------------------ #
    RATE_LIMIT = int(os.getenv('NIS2_RATE_LIMIT', '100'))  # requests / minute / IP

    # ------------------------------------------------------------------ #
    # File uploads                                                         #
    # ------------------------------------------------------------------ #
    MAX_CONTENT_LENGTH = int(os.getenv('NIS2_MAX_UPLOAD_BYTES', str(20 * 1024 * 1024)))
    UPLOAD_DIR = os.getenv('NIS2_UPLOAD_DIR', '/app/uploads')
