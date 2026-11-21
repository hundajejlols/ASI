"""
Agregacje serwerowe dla Dashboardu (skalowalne >10 000 hostów bez limit=200 w przeglądarce):
  - prawdziwe liczniki KPI z SQL,
  - oś czasu zmian (wizualizacja zmian w czasie),
  - rozkład zmian wg pory dnia (dzień 06:00-22:00 vs noc 22:00-06:00 Europe/Warsaw),
  - grupowanie podobnych usług (po technologii, produkcie/wersji i favicon_mmh3_hash).
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import Principal, require_permission
from app.db.models import ChangeEvent, CustomSignature, Host, Service, SignatureMatch
from app.db.session import get_db
from app.services.queries import fetch_latest_http_fingerprints

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(
    days: int = Query(default=14, ge=1, le=90),
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    # 1. Prawdziwe liczniki hostów wg statusu z całej tabeli hosts
    host_counts_rows = db.execute(
        select(Host.status, func.count(Host.id)).group_by(Host.status)
    ).all()
    status_counts = {str(st): int(cnt) for st, cnt in host_counts_rows}
    total_hosts = sum(status_counts.values())

    # 2. Prawdziwa liczba otwartych usług (dla hostów nie-offline/archived)
    total_open_services = int(
        db.execute(
            select(func.count(Service.id))
            .join(Host, Host.id == Service.host_id)
            .where(Service.state == "open", Host.status.notin_(["offline", "archived"]))
        ).scalar_one()
    )

    # 3. Prawdziwa liczba wszystkich zdarzeń Diff i unikalnych aktywnych dopasowań sygnatur
    total_changes = int(db.execute(select(func.count(ChangeEvent.id))).scalar_one())
    active_sig_matches = int(
        db.execute(
            select(func.count(SignatureMatch.id))
            .join(CustomSignature, CustomSignature.id == SignatureMatch.signature_id)
            .join(Service, Service.id == SignatureMatch.service_id)
            .join(Host, Host.id == Service.host_id)
            .where(
                CustomSignature.is_enabled.is_(True),
                Service.state == "open",
                Host.status.notin_(["offline", "archived"]),
            )
        ).scalar_one()
    )

    # 4. Wizualizacja zmian w czasie (ostatnie N dni) + podział pora dnia (dzień 06-22 vs noc 22-06)
    warsaw_tz = ZoneInfo("Europe/Warsaw")
    since = datetime.now(timezone.utc) - timedelta(days=days)
    recent_events = db.execute(
        select(ChangeEvent.detected_at, ChangeEvent.change_type, ChangeEvent.severity)
        .where(ChangeEvent.detected_at >= since)
        .order_by(ChangeEvent.detected_at)
    ).all()

    timeline_map: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "high_or_med": 0, "new": 0, "offline": 0})
    day_vs_night = {
        "day_06_22": {"total": 0, "host_offline": 0, "host_recovered": 0, "service_changes": 0},
        "night_22_06": {"total": 0, "host_offline": 0, "host_recovered": 0, "service_changes": 0},
    }
    by_type_counter: Counter[str] = Counter()

    for dt, ctype, sev in recent_events:
        local_dt = dt.astimezone(warsaw_tz)
        day_key = local_dt.strftime("%Y-%m-%d")
        timeline_map[day_key]["total"] += 1
        if sev in ("medium", "high", "critical"):
            timeline_map[day_key]["high_or_med"] += 1
        if ctype in ("host_new", "service_new"):
            timeline_map[day_key]["new"] += 1
        if ctype in ("host_offline", "service_closed"):
            timeline_map[day_key]["offline"] += 1

        bucket = "day_06_22" if 6 <= local_dt.hour < 22 else "night_22_06"
        day_vs_night[bucket]["total"] += 1
        if ctype == "host_offline":
            day_vs_night[bucket]["host_offline"] += 1
        elif ctype == "host_recovered":
            day_vs_night[bucket]["host_recovered"] += 1
        elif ctype in ("service_new", "service_closed", "service_changed", "tls_changed", "tech_changed"):
            day_vs_night[bucket]["service_changes"] += 1

        by_type_counter[str(ctype)] += 1

    changes_timeline = [
        {"date": k, **v} for k, v in sorted(timeline_map.items())
    ]

    # 5. Grupowanie podobnych usług (po technologii, produkcie/wersji i favicon MMH3)
    open_services = db.execute(
        select(Service, Host.ip_address)
        .join(Host, Host.id == Service.host_id)
        .where(Service.state == "open", Host.status.notin_(["offline", "archived"]))
        .limit(5000)
    ).all()

    svc_ids = [s.id for s, _ in open_services]
    latest_fps = fetch_latest_http_fingerprints(db, svc_ids)

    by_tech: dict[str, set[str]] = defaultdict(set)
    by_product: dict[str, set[str]] = defaultdict(set)
    by_favicon: dict[str, set[str]] = defaultdict(set)

    for svc, ip_val in open_services:
        ip_str = str(ip_val).split("/")[0]
        endpoint = f"{ip_str}:{svc.port}"
        prod_label = f"{svc.product or svc.service_name or 'unknown'} {svc.version or ''}".strip()
        by_product[prod_label].add(endpoint)

        fp = latest_fps.get(svc.id)
        if fp:
            for tech in fp.technologies or []:
                if tech:
                    by_tech[str(tech)].add(endpoint)
            if fp.favicon_mmh3_hash:
                by_favicon[str(fp.favicon_mmh3_hash)].add(endpoint)

    def _top_groups(mapping: dict[str, set[str]], limit: int = 12) -> list[dict[str, Any]]:
        ranked = sorted(mapping.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
        return [
            {"key": k, "count": len(v), "sample_endpoints": sorted(v)[:5]}
            for k, v in ranked
        ]

    return {
        "kpi": {
            "total_hosts": total_hosts,
            "online_hosts": status_counts.get("online", 0),
            "unstable_hosts": status_counts.get("unstable", 0),
            "offline_hosts": status_counts.get("offline", 0),
            "archived_hosts": status_counts.get("archived", 0),
            "total_open_services": total_open_services,
            "total_changes": total_changes,
            "active_signature_matches": active_sig_matches,
        },
        "changes_timeline": changes_timeline,
        "changes_by_type": dict(by_type_counter),
        "time_of_day_analysis": day_vs_night,
        "service_groups": {
            "by_technology": _top_groups(by_tech),
            "by_product": _top_groups(by_product),
            "by_favicon_mmh3": _top_groups(by_favicon),
        },
    }
