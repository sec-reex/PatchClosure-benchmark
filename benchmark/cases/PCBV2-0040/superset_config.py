"""Minimal Superset configuration for PatchClosure-Bench.
Uses SQLite for metadata (avoids version conflicts across profiles).
Postgres is used only as a DATA source (where the canary lives).
"""
import os

SECRET_KEY = os.environ.get("SUPERSET_SECRET_KEY", "pcb_benchmark_key")

# SQLite for Superset metadata — each profile gets its own DB inside the container
SQLALCHEMY_DATABASE_URI = "sqlite:////app/superset_home/superset.db"

# Redis for caching
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": 1,
}

DATA_CACHE_CONFIG = CACHE_CONFIG.copy()

RESULTS_BACKEND = None

class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

CELERY_CONFIG = CeleryConfig

# Disable security features that interfere with API testing
WTF_CSRF_ENABLED = False
TALISMAN_ENABLED = False

# CORS: only enable if flask-cors is installed (lean images may lack it)
try:
    import flask_cors  # noqa: F401
    ENABLE_CORS = True
    CORS_OPTIONS = {
        "supports_credentials": True,
        "resources": {r"/api/*": {"origins": "*"}},
    }
except ImportError:
    ENABLE_CORS = False

# Feature flags
FEATURE_FLAGS = {
    "ENABLE_TEMPLATE_PROCESSING": True,
}

# Prevent Superset from trying to load examples
SUPERSET_LOAD_EXAMPLES = False
