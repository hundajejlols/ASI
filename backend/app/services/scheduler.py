"""
Serwis harmonogramu cyklicznych skanów i okien czasowych (scan_schedules).
Obsługuje:
  - walidację i dopasowanie 5-polowych wyrażeń cron (minuta godzina dzień miesiąc dzień_tyg),
  - przedziały czasowe okien serwisowych (w tym przejście przez północ, np. 22:00-06:00),
  - automatyczne uruchamianie cyklicznych skanów w oknie czasowym,
  - automatyczne wznawianie przerwanych skanów (paused_window) po otwarciu kolejnego okna.
"""

from datetime import datetime, time, timedelta, timezone
import logging
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import ScanRun, ScanSchedule
from app.services.chunker import reconcile_stale_scan_runs, resume_scan_run, start_scan_run

logger = logging.getLogger(__name__)


def _resolve_tz(tz_name: str | None):
    if not tz_name or tz_name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def _parse_cron_field(field: str, min_val: int, max_val: int) -> set[int]:
    values: set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"Pusty fragment wyrażenia cron: {field!r}")
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            if not step_str.isdigit() or int(step_str) < 1:
                raise ValueError(f"Nieprawidłowy krok cron: {part!r}")
            step = int(step_str)
        else:
            base = part

        if base == "*":
            start, end = min_val, max_val
        elif "-" in base:
            lo_s, hi_s = base.split("-", 1)
            if not lo_s.isdigit() or not hi_s.isdigit():
                raise ValueError(f"Nieprawidłowy zakres cron: {part!r}")
            start, end = int(lo_s), int(hi_s)
            if start < min_val or end > max_val or start > end:
                raise ValueError(f"Zakres cron poza granicami [{min_val}..{max_val}]: {part!r}")
        else:
            if not base.isdigit():
                raise ValueError(f"Nieprawidłowa wartość cron: {part!r}")
            val = int(base)
            if val < min_val or val > max_val:
                raise ValueError(f"Wartość cron poza granicami [{min_val}..{max_val}]: {part!r}")
            if "/" in part:
                start, end = val, max_val
            else:
                values.add(val)
                continue

        for v in range(start, end + 1, step):
            values.add(v)
    return values


def validate_cron_expression(cron_expr: str) -> str:
    """Waliduje standardowe 5-polowe wyrażenie cron (np. '0 22 * * *', '*/30 * * * *')."""
    cleaned = " ".join((cron_expr or "").strip().split())
    parts = cleaned.split(" ")
    if len(parts) != 5:
        raise ValueError(
            "Wyrażenie cron musi składać się z dokładnie 5 pól: minuta godzina dzień_miesiąca miesiąc dzień_tygodnia (np. '0 22 * * *')."
        )
    _parse_cron_field(parts[0], 0, 59)
    _parse_cron_field(parts[1], 0, 23)
    _parse_cron_field(parts[2], 1, 31)
    _parse_cron_field(parts[3], 1, 12)
    _parse_cron_field(parts[4], 0, 7)
    return cleaned


def cron_matches(cron_expr: str, dt: datetime) -> bool:
    """Sprawdza, czy podana chwila `dt` pasuje do 5-polowego wyrażenia cron."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False
    mins = _parse_cron_field(parts[0], 0, 59)
    hours = _parse_cron_field(parts[1], 0, 23)
    doms = _parse_cron_field(parts[2], 1, 31)
    months = _parse_cron_field(parts[3], 1, 12)
    dows = _parse_cron_field(parts[4], 0, 7)
    if 7 in dows:
        dows.add(0)
    # Python weekday(): Monday=0..Sunday=6 -> cron: Sunday=0, Monday=1..Saturday=6
    cron_dow = (dt.weekday() + 1) % 7
    return (
        dt.minute in mins
        and dt.hour in hours
        and dt.day in doms
        and dt.month in months
        and cron_dow in dows
    )


def is_within_window(now_local: datetime, window_start: time, window_end: time) -> bool:
    """
    Sprawdza, czy aktualny czas lokalny mieści się w oknie [window_start, window_end).
    Obsługuje zarówno okna dzienne (np. 08:00-16:00), jak i nocne przechodzące przez północ (22:00-06:00)
    oraz okno całodobowe (window_start == window_end).
    """
    t = now_local.time().replace(tzinfo=None)
    start = window_start.replace(tzinfo=None)
    end = window_end.replace(tzinfo=None)
    if start == end:
        return True
    if start < end:
        return start <= t < end
    # Przejście przez północ (np. 22:00 -> 06:00)
    return t >= start or t < end


def remaining_window_minutes(now_local: datetime, window_start: time, window_end: time) -> int:
    """Zwraca liczbę pełnych minut pozostałych do końca bieżącego aktywnego okna (minimum 1, maks. 1440)."""
    start = window_start.replace(tzinfo=None)
    end = window_end.replace(tzinfo=None)
    if start == end:
        return 1440

    end_dt = now_local.replace(
        hour=end.hour,
        minute=end.minute,
        second=end.second,
        microsecond=0,
    )
    if end_dt <= now_local:
        end_dt = end_dt + timedelta(days=1)

    mins = int((end_dt - now_local).total_seconds() // 60)
    return max(1, min(1440, mins))


def tick_schedules(db: Session, now_utc: datetime | None = None) -> dict[str, Any]:
    """
    Pojedynczy cykl harmonogramu:
    1. Dla każdego aktywnego harmonogramu będącego w swoim oknie czasowym:
       - jeśli ma przerwany skan (`paused_window`), automatycznie go wznawia w bieżącym oknie;
       - w przeciwnym razie, jeśli pasuje `cron_expression` i nie uruchomiono go w tej minucie,
         uruchamia nowy skan powiązany z harmonogramem.
    """
    now = now_utc or datetime.now(timezone.utc)
    reconciled = reconcile_stale_scan_runs(db)
    schedules = db.execute(
        select(ScanSchedule).where(ScanSchedule.is_enabled.is_(True))
    ).scalars().all()

    resumed_ids: list[str] = []
    started_ids: list[str] = []
    skipped: list[dict[str, str]] = []

    for sched in schedules:
        tz = _resolve_tz(sched.timezone)
        now_local = now.astimezone(tz)
        if not is_within_window(now_local, sched.window_start_utc, sched.window_end_utc):
            skipped.append({"schedule": sched.name, "reason": "outside_window"})
            continue

        win_mins = remaining_window_minutes(now_local, sched.window_start_utc, sched.window_end_utc)

        # Czy istnieje już aktywny skan z tego harmonogramu?
        active_run = db.execute(
            select(ScanRun)
            .where(
                ScanRun.schedule_id == sched.id,
                ScanRun.status.in_(["queued", "running"]),
            )
            .order_by(desc(ScanRun.created_at))
            .limit(1)
        ).scalar_one_or_none()
        if active_run is not None:
            skipped.append({"schedule": sched.name, "reason": "already_running"})
            continue

        # 1. Automatyczne wznowienie przerwanego skanu (paused_window) w kolejnym oknie
        paused_run = db.execute(
            select(ScanRun)
            .where(
                ScanRun.schedule_id == sched.id,
                ScanRun.status == "paused_window",
            )
            .order_by(desc(ScanRun.created_at))
            .limit(1)
        ).scalar_one_or_none()

        if paused_run is not None:
            # Nie wznawiaj natychmiast w tej samej minucie, w której został zapauzowany
            if paused_run.paused_at and (now - paused_run.paused_at).total_seconds() < 60:
                skipped.append({"schedule": sched.name, "reason": "cooldown_after_pause"})
                continue
            try:
                res = resume_scan_run(db, scan_run_id=paused_run.id, window_minutes=win_mins)
                if res.get("resumed"):
                    resumed_ids.append(str(paused_run.id))
                    logger.info(
                        "Harmonogram '%s' automatycznie wznowił skan %s (okno=%d min).",
                        sched.name,
                        paused_run.id,
                        win_mins,
                    )
            except Exception as exc:
                logger.warning("Nie udało się wznowić skanu z harmonogramu '%s': %s", sched.name, exc)
            continue

        # 2. Sprawdzenie crona i uruchomienie nowego skanu cyklicznego
        if not cron_matches(sched.cron_expression, now_local):
            skipped.append({"schedule": sched.name, "reason": "cron_not_due"})
            continue

        latest_run = db.execute(
            select(ScanRun)
            .where(ScanRun.schedule_id == sched.id)
            .order_by(desc(ScanRun.created_at))
            .limit(1)
        ).scalar_one_or_none()
        if latest_run and latest_run.created_at:
            latest_local = latest_run.created_at.astimezone(tz)
            if (
                latest_local.year == now_local.year
                and latest_local.month == now_local.month
                and latest_local.day == now_local.day
                and latest_local.hour == now_local.hour
                and latest_local.minute == now_local.minute
            ):
                skipped.append({"schedule": sched.name, "reason": "already_triggered_this_minute"})
                continue

        try:
            res = start_scan_run(
                db,
                schedule_id=sched.id,
                target_group_id=sched.target_group_id,
                profile_id=sched.profile_id,
                window_minutes=win_mins,
                dry_run=False,
            )
            started_ids.append(str(res["scan_run_id"]))
            logger.info(
                "Harmonogram '%s' uruchomił cykliczny skan %s (okno=%d min).",
                sched.name,
                res["scan_run_id"],
                win_mins,
            )
        except Exception as exc:
            logger.warning("Harmonogram '%s' nie uruchomił skanu: %s", sched.name, exc)
            skipped.append({"schedule": sched.name, "reason": str(exc)})

    return {
        "evaluated_at_utc": now.isoformat(),
        "reconciled_stale_runs": reconciled,
        "schedules_checked": len(schedules),
        "started_runs": started_ids,
        "resumed_runs": resumed_ids,
        "skipped": skipped,
    }
