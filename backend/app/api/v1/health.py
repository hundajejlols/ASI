import redis
from fastapi import APIRouter

from app.core.config import settings
from app.db.session import check_db_health

router = APIRouter(tags=["health"])


def _check_redis() -> bool:
    try:
        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        return bool(client.ping())
    except Exception:
        return False


@router.get("/health")
def health_check() -> dict:
    db_ok = check_db_health()
    redis_ok = _check_redis()
    return {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "services": {
            "postgres": "up" if db_ok else "down",
            "redis": "up" if redis_ok else "down",
        },
    }
