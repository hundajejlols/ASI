"""
Agregacje serwerowe dla Dashboardu (skalowalne >10 000 hostów bez limit=200 w przeglądarce):
  - prawdziwe liczniki KPI z SQL,
  - oś czasu zmian (wizualizacja zmian w czasie),
  - rozkład zmian wg pory dnia (dzień 06:00-22:00 vs noc 22:00-06:00 Europe/Warsaw),
  - grupowanie podobnych usług (po technologii, produkcie/wersji i favicon_mmh3_hash).
"""

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.orm import Session

from app.core.security import Principal, require_permission
from app.db.models import ChangeEvent, CustomSignature, Host, Service, SignatureMatch
from app.db.session import get_db
from app.services.queries import fetch_latest_http_fingerprints
from app.services.scope import resolve_principal_scope

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    scope = resolve_principal_scope(db, principal)
    scope_flt = scope.sql_host_filter()

    # 1. Prawdziwe liczniki hostów wg statusu z całej tabeli hosts (z uwzględnieniem zakresu konta)
    host_counts_stmt = select(Host.status, func.count(Host.id)).group_by(Host.status)
    if scope_flt is not None:
        host_counts_stmt = host_counts_stmt.where(scope_flt)
    host_counts_rows = db.execute(host_counts_stmt).all()
    status_counts = {str(st): int(cnt) for st, cnt in host_counts_rows}
    total_hosts = sum(status_counts.values())

    # 2. Prawdziwa liczba otwartych usług (dla hostów nie-offline/archived)
    open_svc_count_stmt = (
        select(func.count(Service.id))
        .join(Host, Host.id == Service.host_id)
        .where(Service.state == "open", Host.status.notin_(["offline", "archived"]))
    )
    if scope_flt is not None:
        open_svc_count_stmt = open_svc_count_stmt.where(scope_flt)
    total_open_services = int(db.execute(open_svc_count_stmt).scalar_one())

    # 3. Prawdziwa liczba wszystkich zdarzeń Diff i unikalnych aktywnych dopasowań sygnatur
    total_changes_stmt = select(func.count(ChangeEvent.id))
    if scope_flt is not None:
        total_changes_stmt = total_changes_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    total_changes = int(db.execute(total_changes_stmt).scalar_one())

    active_sig_stmt = (
        select(func.count(SignatureMatch.id))
        .join(CustomSignature, CustomSignature.id == SignatureMatch.signature_id)
        .join(Service, Service.id == SignatureMatch.service_id)
        .join(Host, Host.id == Service.host_id)
        .where(
            CustomSignature.is_enabled.is_(True),
            Service.state == "open",
            Host.status.notin_(["offline", "archived"]),
        )
    )
    if scope_flt is not None:
        active_sig_stmt = active_sig_stmt.where(scope_flt)
    active_sig_matches = int(db.execute(active_sig_stmt).scalar_one())

    # 4. Wizualizacja zmian w czasie (ostatnie N dni, ciągła oś dzienna) + podział pora dnia (dzień 06-22 vs noc 22-06)
    warsaw_tz = ZoneInfo("Europe/Warsaw")
    today_local = datetime.now(warsaw_tz).date()
    start_date_local = today_local - timedelta(days=days - 1)
    since = datetime(start_date_local.year, start_date_local.month, start_date_local.day, tzinfo=warsaw_tz).astimezone(timezone.utc)

    day_local_col = func.date_trunc("day", func.timezone("Europe/Warsaw", ChangeEvent.detected_at))
    timeline_stmt = (
        select(
            day_local_col.label("day"),
            func.count(ChangeEvent.id).label("total"),
            func.sum(
                case((ChangeEvent.severity.in_(["medium", "high", "critical"]), 1), else_=0)
            ).label("high_or_med"),
            func.sum(
                case((ChangeEvent.change_type.in_(["host_new", "service_new"]), 1), else_=0)
            ).label("new_cnt"),
            func.sum(
                case((ChangeEvent.change_type.in_(["host_offline", "service_closed"]), 1), else_=0)
            ).label("offline_cnt"),
            func.sum(
                case((ChangeEvent.change_type == "tls_changed", 1), else_=0)
            ).label("tls_cnt"),
            func.sum(
                case((ChangeEvent.change_type == "tech_changed", 1), else_=0)
            ).label("tech_cnt"),
        )
        .where(ChangeEvent.detected_at >= since)
        .group_by(day_local_col)
        .order_by(day_local_col.asc())
    )
    if scope_flt is not None:
        timeline_stmt = timeline_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    timeline_rows = db.execute(timeline_stmt).all()

    timeline_map: dict[str, dict[str, int]] = {}
    for row in timeline_rows:
        if row.day:
            d_key = row.day.date().isoformat()
            timeline_map[d_key] = {
                "total": int(row.total or 0),
                "high_or_med": int(row.high_or_med or 0),
                "new": int(row.new_cnt or 0),
                "offline": int(row.offline_cnt or 0),
                "tls_changed": int(row.tls_cnt or 0),
                "tech_changed": int(row.tech_cnt or 0),
            }

    changes_timeline = []
    for offset_day in range(days):
        d_key = (start_date_local + timedelta(days=offset_day)).isoformat()
        entry = timeline_map.get(d_key)
        changes_timeline.append(
            {
                "date": d_key,
                "total": entry["total"] if entry else 0,
                "high_or_med": entry["high_or_med"] if entry else 0,
                "new": entry["new"] if entry else 0,
                "offline": entry["offline"] if entry else 0,
                "tls_changed": entry["tls_changed"] if entry else 0,
                "tech_changed": entry["tech_changed"] if entry else 0,
            }
        )

    hour_local_col = cast(func.extract("hour", func.timezone("Europe/Warsaw", ChangeEvent.detected_at)), Integer)
    tod_stmt = (
        select(
            case((hour_local_col.between(6, 21), "day_06_22"), else_="night_22_06").label("period"),
            func.count(ChangeEvent.id).label("total"),
            func.sum(case((ChangeEvent.change_type == "host_offline", 1), else_=0)).label("host_offline"),
            func.sum(case((ChangeEvent.change_type == "host_recovered", 1), else_=0)).label("host_recovered"),
            func.sum(
                case((ChangeEvent.change_type.in_(["service_new", "service_closed", "service_changed", "tls_changed", "tech_changed"]), 1), else_=0)
            ).label("service_changes"),
        )
        .where(ChangeEvent.detected_at >= since)
        .group_by("period")
    )
    if scope_flt is not None:
        tod_stmt = tod_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    tod_rows = db.execute(tod_stmt).all()

    day_vs_night = {
        "day_06_22": {"total": 0, "host_offline": 0, "host_recovered": 0, "service_changes": 0},
        "night_22_06": {"total": 0, "host_offline": 0, "host_recovered": 0, "service_changes": 0},
    }
    for r in tod_rows:
        if r.period in day_vs_night:
            day_vs_night[r.period] = {
                "total": int(r.total or 0),
                "host_offline": int(r.host_offline or 0),
                "host_recovered": int(r.host_recovered or 0),
                "service_changes": int(r.service_changes or 0),
            }

    type_summary_stmt = (
        select(ChangeEvent.change_type, func.count(ChangeEvent.id).label("cnt"))
        .where(ChangeEvent.detected_at >= since)
        .group_by(ChangeEvent.change_type)
    )
    if scope_flt is not None:
        type_summary_stmt = type_summary_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    type_summary_rows = db.execute(type_summary_stmt).all()
    by_type_counter = {str(r.change_type): int(r.cnt or 0) for r in type_summary_rows}

    # 5. Grupowanie podobnych usług (po technologii, produkcie/wersji i favicon MMH3)
    open_svc_stmt = (
        select(Service, Host.ip_address)
        .join(Host, Host.id == Service.host_id)
        .where(Service.state == "open", Host.status.notin_(["offline", "archived"]))
        .limit(5000)
    )
    if scope_flt is not None:
        open_svc_stmt = open_svc_stmt.where(scope_flt)
    open_services = db.execute(open_svc_stmt).all()

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


@router.get("/timeline-day")
def get_timeline_day_details(
    target_date: date = Query(..., alias="date"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("read")),
) -> dict[str, Any]:
    scope = resolve_principal_scope(db, principal)
    scope_flt = scope.sql_host_filter()

    warsaw_tz = ZoneInfo("Europe/Warsaw")
    day_start = datetime(target_date.year, target_date.month, target_date.day, tzinfo=warsaw_tz).astimezone(timezone.utc)
    day_end = (datetime(target_date.year, target_date.month, target_date.day, tzinfo=warsaw_tz) + timedelta(days=1)).astimezone(timezone.utc)

    hour_col = cast(func.extract("hour", func.timezone("Europe/Warsaw", ChangeEvent.detected_at)), Integer)
    hourly_stmt = (
        select(
            hour_col.label("hr"),
            func.count(ChangeEvent.id).label("total"),
            func.sum(
                case((ChangeEvent.severity.in_(["high", "critical", "medium"]), 1), else_=0)
            ).label("high_or_med"),
            func.sum(
                case((ChangeEvent.change_type.in_(["host_new", "service_new"]), 1), else_=0)
            ).label("new_cnt"),
            func.sum(
                case((ChangeEvent.change_type.in_(["host_offline", "service_closed"]), 1), else_=0)
            ).label("offline_cnt"),
        )
        .where(ChangeEvent.detected_at >= day_start, ChangeEvent.detected_at < day_end)
        .group_by(hour_col)
        .order_by(hour_col.asc())
    )
    if scope_flt is not None:
        hourly_stmt = hourly_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    hourly_rows = db.execute(hourly_stmt).all()

    hourly_map = {
        int(r.hr): {
            "total": int(r.total or 0),
            "high_or_med": int(r.high_or_med or 0),
            "new": int(r.new_cnt or 0),
            "offline": int(r.offline_cnt or 0),
        }
        for r in hourly_rows
        if r.hr is not None
    }
    hourly = [
        {
            "hour": h,
            "total": hourly_map.get(h, {}).get("total", 0),
            "high_or_med": hourly_map.get(h, {}).get("high_or_med", 0),
            "new": hourly_map.get(h, {}).get("new", 0),
            "offline": hourly_map.get(h, {}).get("offline", 0),
        }
        for h in range(24)
    ]

    type_stmt = (
        select(ChangeEvent.change_type, func.count(ChangeEvent.id).label("cnt"))
        .where(ChangeEvent.detected_at >= day_start, ChangeEvent.detected_at < day_end)
        .group_by(ChangeEvent.change_type)
        .order_by(func.count(ChangeEvent.id).desc())
    )
    if scope_flt is not None:
        type_stmt = type_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    type_rows = db.execute(type_stmt).all()

    sev_stmt = (
        select(ChangeEvent.severity, func.count(ChangeEvent.id).label("cnt"))
        .where(ChangeEvent.detected_at >= day_start, ChangeEvent.detected_at < day_end)
        .group_by(ChangeEvent.severity)
    )
    if scope_flt is not None:
        sev_stmt = sev_stmt.join(Host, Host.id == ChangeEvent.host_id).where(scope_flt)
    sev_rows = db.execute(sev_stmt).all()

    sample_stmt = (
        select(ChangeEvent, Host.ip_address, Service.port, Service.protocol)
        .join(Host, Host.id == ChangeEvent.host_id)
        .outerjoin(Service, Service.id == ChangeEvent.service_id)
        .where(ChangeEvent.detected_at >= day_start, ChangeEvent.detected_at < day_end)
        .order_by(ChangeEvent.detected_at.desc())
        .limit(20)
    )
    if scope_flt is not None:
        sample_stmt = sample_stmt.where(scope_flt)
    sample_rows = db.execute(sample_stmt).all()

    total_day = sum(h["total"] for h in hourly)
    return {
        "date": target_date.isoformat(),
        "total": total_day,
        "hourly": hourly,
        "by_type": [{"change_type": r.change_type, "count": int(r.cnt or 0)} for r in type_rows],
        "by_severity": {r.severity: int(r.cnt or 0) for r in sev_rows},
        "sample_events": [
            {
                "id": str(ev.id),
                "host_ip": str(host_ip).split("/")[0] if host_ip else None,
                "service_port": port,
                "service_protocol": protocol,
                "change_type": ev.change_type,
                "severity": ev.severity,
                "detected_at": ev.detected_at.astimezone(warsaw_tz).isoformat(),
            }
            for ev, host_ip, port, protocol in sample_rows
        ],
    }

