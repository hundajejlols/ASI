"""
Zoptymalizowane zapytania batchowe do PostgreSQL (eliminacja problemu N+1 przy >10 000 hostów).
"""

from uuid import UUID
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import HTTPFingerprint


def fetch_latest_http_fingerprints(
    db: Session,
    service_ids: list[UUID],
) -> dict[UUID, HTTPFingerprint]:
    """
    Pobiera najnowszy rekord HTTPFingerprint dla każdej usługi z `service_ids`
    w JEDNYM zapytaniu SQL (PostgreSQL DISTINCT ON (service_id)) zamiast N osobnych zapytań.
    """
    if not service_ids:
        return {}
    stmt = (
        select(HTTPFingerprint)
        .where(HTTPFingerprint.service_id.in_(service_ids))
        .distinct(HTTPFingerprint.service_id)
        .order_by(HTTPFingerprint.service_id, desc(HTTPFingerprint.captured_at))
    )
    rows = db.execute(stmt).scalars().all()
    return {fp.service_id: fp for fp in rows}
