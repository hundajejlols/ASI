import {
  BarChart3,
  Calendar,
  ChevronLeft,
  ChevronRight,
  Clock,
  Moon,
  RotateCcw,
  Sun,
  X,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { apiFetch } from '../api';
import type { DashboardSummary, TimelineDayDetails, UserRole } from '../types';
import { ChangeTypeBadge, SeverityBadge } from './Badges';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

type TimelinePoint = DashboardSummary['changes_timeline'][number];
type MetricFilter = 'all' | 'new' | 'offline' | 'high_or_med';

interface Props {
  role: UserRole;
  initialTimeline: TimelinePoint[];
  dayStats?: DashboardSummary['time_of_day_analysis']['day_06_22'];
  nightStats?: DashboardSummary['time_of_day_analysis']['night_22_06'];
}

const CHART_W = 800;
const CHART_H = 210;
const PAD_L = 46;
const PAD_R = 14;
const PAD_T = 16;
const PAD_B = 28;
const PLOT_W = CHART_W - PAD_L - PAD_R;
const PLOT_H = CHART_H - PAD_T - PAD_B;

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

function formatShortDate(iso: string): string {
  // iso: YYYY-MM-DD
  const [, m, d] = iso.split('-');
  return `${d}.${m}`;
}

function formatFullDate(iso: string): string {
  const [y, m, d] = iso.split('-').map(Number);
  if (!y || !m || !d) return iso;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.toLocaleDateString('pl-PL', {
    weekday: 'short',
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

function formatCompactNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${(n / 1_000).toFixed(0)}k`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export function ChangesTimelineChart({ role, initialTimeline, dayStats, nightStats }: Props) {
  const [fullTimeline, setFullTimeline] = useState<TimelinePoint[]>(initialTimeline);
  const [viewStart, setViewStart] = useState<number>(() => Math.max(0, initialTimeline.length - 14));
  const [viewEnd, setViewEnd] = useState<number>(() => Math.max(14, initialTimeline.length));
  const [metric, setMetric] = useState<MetricFilter>('all');
  const [logScale, setLogScale] = useState<boolean>(false);

  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [mousePos, setMousePos] = useState<{ x: number; y: number } | null>(null);

  const [selectedDate, setSelectedDate] = useState<string | null>(null);
  const [dayDetails, setDayDetails] = useState<TimelineDayDetails | null>(null);
  const [dayLoading, setDayLoading] = useState<boolean>(false);
  const [dayError, setDayError] = useState<string | null>(null);
  const [hoverHour, setHoverHour] = useState<number | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const dragRef = useRef<{
    active: boolean;
    startX: number;
    startViewStart: number;
    startViewEnd: number;
    moved: boolean;
  }>({ active: false, startX: 0, startViewStart: 0, startViewEnd: 0, moved: false });

  // Keep initialTimeline synced when parent refreshes, and lazily load 365 days for deep zoom-out
  useEffect(() => {
    if (initialTimeline.length > fullTimeline.length) {
      setFullTimeline(initialTimeline);
    }
  }, [initialTimeline, fullTimeline.length]);

  useEffect(() => {
    let cancelled = false;
    apiFetch<DashboardSummary>('/dashboard/summary?days=365', role)
      .then((res) => {
        if (cancelled || !res.changes_timeline?.length) return;
        const newLen = res.changes_timeline.length;
        setFullTimeline((prev) => {
          const delta = newLen - prev.length;
          if (delta > 0) {
            setViewStart((vs) => vs + delta);
            setViewEnd((ve) => ve + delta);
          }
          return res.changes_timeline;
        });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [role]);

  // Adjust initial viewport if timeline was empty at mount
  useEffect(() => {
    if (fullTimeline.length > 0 && viewEnd === 0) {
      setViewStart(Math.max(0, fullTimeline.length - 14));
      setViewEnd(fullTimeline.length);
    }
  }, [fullTimeline.length, viewEnd]);

  // Fetch selected day hourly & event breakdown
  useEffect(() => {
    if (!selectedDate) {
      setDayDetails(null);
      setDayError(null);
      return;
    }
    let cancelled = false;
    setDayLoading(true);
    setDayError(null);
    apiFetch<TimelineDayDetails>(`/dashboard/timeline-day?date=${encodeURIComponent(selectedDate)}`, role)
      .then((res) => {
        if (!cancelled) setDayDetails(res);
      })
      .catch((err) => {
        if (!cancelled) setDayError(err instanceof Error ? err.message : 'Błąd pobierania szczegółów dnia');
      })
      .finally(() => {
        if (!cancelled) setDayLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedDate, role]);

  const totalDays = fullTimeline.length;
  const span = Math.max(3, viewEnd - viewStart);

  // Non-passive wheel listener for smooth zoom anchored at cursor
  useEffect(() => {
    const el = containerRef.current;
    if (!el || totalDays === 0) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const relX = clamp((e.clientX - rect.left) / rect.width, 0, 1);
      const plotRatio = clamp((relX * CHART_W - PAD_L) / PLOT_W, 0, 1);

      // Horizontal scroll / shift+wheel pans; vertical scroll zooms
      if (Math.abs(e.deltaX) > Math.abs(e.deltaY) || e.shiftKey) {
        const delta = (Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY) * 0.025;
        setViewStart((prevStart) => {
          const curSpan = viewEnd - prevStart;
          const shift = delta * (curSpan / 14);
          const nextStart = clamp(prevStart + shift, 0, Math.max(0, totalDays - curSpan));
          setViewEnd(nextStart + curSpan);
          return nextStart;
        });
        return;
      }

      const zoomFactor = Math.exp(e.deltaY * 0.0022);
      setViewStart((prevStart) => {
        const curSpan = viewEnd - prevStart;
        const nextSpan = clamp(curSpan * zoomFactor, Math.min(3, totalDays), totalDays);
        const anchorDataIdx = prevStart + plotRatio * curSpan;
        let nextStart = anchorDataIdx - plotRatio * nextSpan;
        let nextEnd = nextStart + nextSpan;
        if (nextStart < 0) {
          nextStart = 0;
          nextEnd = nextSpan;
        }
        if (nextEnd > totalDays) {
          nextEnd = totalDays;
          nextStart = Math.max(0, totalDays - nextSpan);
        }
        setViewEnd(nextEnd);
        return nextStart;
      });
    };

    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, [totalDays, viewEnd]);

  const getMetricValue = useCallback(
    (pt: TimelinePoint): number => {
      if (metric === 'new') return pt.new;
      if (metric === 'offline') return pt.offline;
      if (metric === 'high_or_med') return pt.high_or_med;
      return pt.total;
    },
    [metric]
  );

  const visibleStartIdx = Math.max(0, Math.floor(viewStart));
  const visibleEndIdx = Math.min(totalDays - 1, Math.ceil(viewEnd));

  const maxVal = useMemo(() => {
    let m = 1;
    for (let i = visibleStartIdx; i <= visibleEndIdx; i++) {
      const pt = fullTimeline[i];
      if (pt) {
        const v = getMetricValue(pt);
        if (v > m) m = v;
      }
    }
    return m;
  }, [fullTimeline, visibleStartIdx, visibleEndIdx, getMetricValue]);

  const scaleY = useCallback(
    (val: number): number => {
      if (val <= 0) return 0;
      if (logScale) {
        return Math.log10(val + 1) / Math.log10(maxVal + 1);
      }
      return val / maxVal;
    },
    [logScale, maxVal]
  );

  const setRangeDays = (days: number) => {
    const clamped = Math.min(days, totalDays);
    setViewEnd(totalDays);
    setViewStart(Math.max(0, totalDays - clamped));
  };

  const zoomBy = (factor: number) => {
    const curSpan = viewEnd - viewStart;
    const nextSpan = clamp(curSpan * factor, Math.min(3, totalDays), totalDays);
    const center = (viewStart + viewEnd) / 2;
    let nextStart = center - nextSpan / 2;
    let nextEnd = center + nextSpan / 2;
    if (nextStart < 0) {
      nextStart = 0;
      nextEnd = nextSpan;
    }
    if (nextEnd > totalDays) {
      nextEnd = totalDays;
      nextStart = Math.max(0, totalDays - nextSpan);
    }
    setViewStart(nextStart);
    setViewEnd(nextEnd);
  };

  const jumpToDate = (isoDate: string) => {
    if (!isoDate) return;
    setSelectedDate(isoDate);
    const idx = fullTimeline.findIndex((d) => d.date === isoDate);
    if (idx >= 0) {
      if (idx < viewStart || idx >= viewEnd) {
        const half = span / 2;
        let ns = clamp(idx + 0.5 - half, 0, Math.max(0, totalDays - span));
        setViewStart(ns);
        setViewEnd(Math.min(totalDays, ns + span));
      }
    }
  };

  const stepSelectedDate = (delta: number) => {
    if (!selectedDate) {
      if (totalDays > 0) jumpToDate(fullTimeline[totalDays - 1].date);
      return;
    }
    const idx = fullTimeline.findIndex((d) => d.date === selectedDate);
    if (idx >= 0) {
      const next = clamp(idx + delta, 0, totalDays - 1);
      jumpToDate(fullTimeline[next].date);
    }
  };

  // Pointer handlers for smooth drag pan + hover crosshair + click-to-inspect
  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    dragRef.current = {
      active: true,
      startX: e.clientX,
      startViewStart: viewStart,
      startViewEnd: viewEnd,
      moved: false,
    };
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const el = containerRef.current;
    if (!el || totalDays === 0) return;
    const rect = el.getBoundingClientRect();

    if (dragRef.current.active) {
      const dx = e.clientX - dragRef.current.startX;
      if (Math.abs(dx) > 4) dragRef.current.moved = true;
      const plotPxWidth = (rect.width * PLOT_W) / CHART_W;
      const curSpan = dragRef.current.startViewEnd - dragRef.current.startViewStart;
      const deltaDays = (-dx / Math.max(1, plotPxWidth)) * curSpan;
      const nextStart = clamp(dragRef.current.startViewStart + deltaDays, 0, Math.max(0, totalDays - curSpan));
      setViewStart(nextStart);
      setViewEnd(nextStart + curSpan);
    }

    const svgX = ((e.clientX - rect.left) / rect.width) * CHART_W;
    const svgY = ((e.clientY - rect.top) / rect.height) * CHART_H;
    if (svgX >= PAD_L && svgX <= CHART_W - PAD_R && svgY >= PAD_T && svgY <= CHART_H - PAD_B) {
      const ratio = (svgX - PAD_L) / PLOT_W;
      const dataPos = viewStart + ratio * span;
      const idx = clamp(Math.floor(dataPos), 0, totalDays - 1);
      setHoverIdx(idx);
      setMousePos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
    } else {
      setHoverIdx(null);
      setMousePos(null);
    }
  };

  const handlePointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!dragRef.current.active) return;
    const wasMoved = dragRef.current.moved;
    dragRef.current.active = false;
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      // ignore
    }
    if (!wasMoved && hoverIdx !== null && fullTimeline[hoverIdx]) {
      const clicked = fullTimeline[hoverIdx].date;
      setSelectedDate((prev) => (prev === clicked ? null : clicked));
    }
  };

  // X-axis tick density based on visible span
  const xTicks = useMemo(() => {
    if (totalDays === 0) return [];
    const maxLabels = 9;
    const step = Math.max(1, Math.ceil(span / maxLabels));
    const ticks: Array<{ idx: number; label: string; x: number }> = [];
    for (let i = visibleStartIdx; i <= visibleEndIdx; i += step) {
      const pt = fullTimeline[i];
      if (!pt) continue;
      const x = PAD_L + ((i + 0.5 - viewStart) / span) * PLOT_W;
      if (x >= PAD_L - 8 && x <= CHART_W - PAD_R + 8) {
        ticks.push({ idx: i, label: formatShortDate(pt.date), x });
      }
    }
    return ticks;
  }, [fullTimeline, totalDays, visibleStartIdx, visibleEndIdx, viewStart, span]);

  const yTicks = useMemo(() => {
    const ratios = [0, 0.25, 0.5, 0.75, 1];
    return ratios.map((r) => {
      const y = PAD_T + PLOT_H * (1 - r);
      const val = logScale
        ? Math.round(Math.pow(10, r * Math.log10(maxVal + 1)) - 1)
        : Math.round(r * maxVal);
      return { y, label: formatCompactNum(val) };
    });
  }, [logScale, maxVal]);

  const barWidth = Math.max(2, Math.min(36, (PLOT_W / span) * 0.72));
  const hoveredPoint = hoverIdx !== null ? fullTimeline[hoverIdx] : null;
  const visibleRangeStart = fullTimeline[visibleStartIdx]?.date ?? '';
  const visibleRangeEnd = fullTimeline[Math.min(totalDays - 1, visibleEndIdx)]?.date ?? '';
  const minDate = fullTimeline[0]?.date ?? '';
  const maxDate = fullTimeline[totalDays - 1]?.date ?? '';

  const visibleTotalChanges = useMemo(() => {
    let sum = 0;
    for (let i = visibleStartIdx; i <= visibleEndIdx; i++) {
      if (fullTimeline[i]) sum += getMetricValue(fullTimeline[i]);
    }
    return sum;
  }, [fullTimeline, visibleStartIdx, visibleEndIdx, getMetricValue]);

  return (
    <Card className="lg:col-span-2">
      <CardHeader className="px-4 py-3 border-b border-border space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" />
            Wizualizacja zmian w czasie
            <Badge variant="secondary" className="font-mono text-[10px] ml-1">
              {Math.round(span)} dni • {visibleTotalChanges.toLocaleString('pl-PL')} zdarzeń
            </Badge>
          </CardTitle>
          {dayStats && nightStats && (
            <div className="flex items-center gap-3 text-[11px] font-mono text-muted-foreground">
              <span className="flex items-center gap-1">
                <Sun className="h-3 w-3" /> Dzień (06–22):{' '}
                <strong className="text-foreground">{dayStats.total.toLocaleString('pl-PL')}</strong>
              </span>
              <span className="flex items-center gap-1">
                <Moon className="h-3 w-3" /> Noc (22–06):{' '}
                <strong className="text-foreground">{nightStats.total.toLocaleString('pl-PL')}</strong>
              </span>
            </div>
          )}
        </div>

        {/* Toolbar: presets, zoom, date picker, metric filter, log scale */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1">
            {[7, 14, 30, 90, 365].map((d) => {
              const active = Math.abs(span - Math.min(d, totalDays)) < 0.8 && Math.abs(viewEnd - totalDays) < 0.8;
              return (
                <Button
                  key={d}
                  size="sm"
                  variant={active ? 'default' : 'outline'}
                  onClick={() => setRangeDays(d)}
                  className="h-6 px-2 text-[10px] font-mono"
                >
                  {d === 365 ? '1R' : `${d}D`}
                </Button>
              );
            })}
            <div className="h-4 w-px bg-border mx-1" />
            <Button
              size="sm"
              variant="outline"
              onClick={() => zoomBy(0.65)}
              title="Przybliż (lub scroll w górę)"
              className="h-6 w-6 p-0"
            >
              <ZoomIn className="h-3 w-3" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => zoomBy(1.5)}
              title="Oddal (lub scroll w dół)"
              className="h-6 w-6 p-0"
            >
              <ZoomOut className="h-3 w-3" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setRangeDays(14)}
              title="Resetuj widok (14 dni)"
              className="h-6 w-6 p-0"
            >
              <RotateCcw className="h-3 w-3" />
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <div className="flex items-center gap-1">
              {(
                [
                  ['all', 'Wszystkie'],
                  ['new', 'Nowe'],
                  ['offline', 'Offline'],
                  ['high_or_med', 'Med/High+'],
                ] as const
              ).map(([k, lbl]) => (
                <Button
                  key={k}
                  size="sm"
                  variant={metric === k ? 'secondary' : 'ghost'}
                  onClick={() => setMetric(k)}
                  className="h-6 px-2 text-[10px] font-mono"
                >
                  {lbl}
                </Button>
              ))}
            </div>
            <Button
              size="sm"
              variant={logScale ? 'default' : 'outline'}
              onClick={() => setLogScale((v) => !v)}
              title="Przełącz skalę liniową / logarytmiczną"
              className="h-6 px-2 text-[10px] font-mono"
            >
              {logScale ? 'Log' : 'Lin'}
            </Button>
            <div className="flex items-center gap-0.5 border border-input rounded px-1 h-6 bg-background">
              <Calendar className="h-3 w-3 text-muted-foreground mr-0.5" />
              <input
                type="date"
                value={selectedDate ?? ''}
                min={minDate}
                max={maxDate}
                onChange={(e) => jumpToDate(e.target.value)}
                aria-label="Wybierz datę do inspekcji"
                className="bg-transparent text-[10px] font-mono text-foreground focus:outline-none w-[104px]"
              />
              <button
                type="button"
                onClick={() => stepSelectedDate(-1)}
                title="Poprzedni dzień"
                className="p-0.5 text-muted-foreground hover:text-foreground"
              >
                <ChevronLeft className="h-3 w-3" />
              </button>
              <button
                type="button"
                onClick={() => stepSelectedDate(1)}
                title="Następny dzień"
                className="p-0.5 text-muted-foreground hover:text-foreground"
              >
                <ChevronRight className="h-3 w-3" />
              </button>
            </div>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-4 space-y-3">
        {totalDays > 0 ? (
          <div
            ref={containerRef}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            onPointerLeave={() => {
              if (!dragRef.current.active) {
                setHoverIdx(null);
                setMousePos(null);
              }
            }}
            onDoubleClick={() => setRangeDays(14)}
            className="relative select-none touch-none cursor-crosshair rounded-md border border-border/60 bg-muted/20 p-1"
          >
            <svg
              viewBox={`0 0 ${CHART_W} ${CHART_H}`}
              className="w-full h-52 overflow-visible block"
              preserveAspectRatio="none"
            >
              <defs>
                <clipPath id="asi-timeline-clip">
                  <rect x={PAD_L} y={PAD_T - 2} width={PLOT_W} height={PLOT_H + 4} />
                </clipPath>
              </defs>

              {/* Horizontal gridlines & Y ticks */}
              {yTicks.map((t, i) => (
                <g key={i}>
                  <line
                    x1={PAD_L}
                    x2={CHART_W - PAD_R}
                    y1={t.y}
                    y2={t.y}
                    stroke="currentColor"
                    className="text-border/60"
                    strokeDasharray={i === 0 ? undefined : '3 3'}
                    strokeWidth={1}
                  />
                  <text
                    x={PAD_L - 6}
                    y={t.y + 3}
                    textAnchor="end"
                    className="fill-muted-foreground text-[10px] font-mono"
                  >
                    {t.label}
                  </text>
                </g>
              ))}

              {/* Bars inside clipped plot area */}
              <g clipPath="url(#asi-timeline-clip)">
                {fullTimeline.slice(visibleStartIdx, visibleEndIdx + 1).map((pt, offset) => {
                  const idx = visibleStartIdx + offset;
                  const val = getMetricValue(pt);
                  const cx = PAD_L + ((idx + 0.5 - viewStart) / span) * PLOT_W;
                  const x = cx - barWidth / 2;
                  const norm = scaleY(val);
                  const h = val > 0 ? Math.max(3, norm * PLOT_H) : 0;
                  const y = PAD_T + PLOT_H - h;
                  const isSelected = selectedDate === pt.date;
                  const isHovered = hoverIdx === idx;

                  // Highlight band for hovered or selected day
                  const bandW = Math.max(barWidth + 4, PLOT_W / span);

                  // Stacked proportions when viewing 'all'
                  const highH =
                    metric === 'all' && pt.total > 0 ? (pt.high_or_med / pt.total) * h : 0;
                  const newH =
                    metric === 'all' && pt.total > 0 ? (pt.new / pt.total) * h : 0;

                  return (
                    <g key={pt.date}>
                      {(isHovered || isSelected) && (
                        <rect
                          x={cx - bandW / 2}
                          y={PAD_T}
                          width={bandW}
                          height={PLOT_H}
                          className={isSelected ? 'fill-primary/15' : 'fill-foreground/5'}
                        />
                      )}
                      {val > 0 ? (
                        <>
                          <rect
                            x={x}
                            y={y}
                            width={barWidth}
                            height={h}
                            rx={Math.min(2, barWidth / 4)}
                            className={
                              metric === 'offline'
                                ? 'fill-rose-500/85'
                                : metric === 'high_or_med'
                                  ? 'fill-amber-500/85'
                                  : metric === 'new'
                                    ? 'fill-emerald-500/85'
                                    : 'fill-primary/80'
                            }
                          />
                          {metric === 'all' && newH > 0 && (
                            <rect
                              x={x}
                              y={PAD_T + PLOT_H - newH}
                              width={barWidth}
                              height={newH}
                              className="fill-emerald-500/80"
                            />
                          )}
                          {metric === 'all' && highH > 0 && (
                            <rect
                              x={x}
                              y={PAD_T + PLOT_H - highH}
                              width={barWidth}
                              height={Math.min(highH, h)}
                              className="fill-amber-500/85"
                            />
                          )}
                        </>
                      ) : (
                        <circle
                          cx={cx}
                          cy={PAD_T + PLOT_H - 1.5}
                          r={1.2}
                          className="fill-muted-foreground/30"
                        />
                      )}
                      {isSelected && (
                        <rect
                          x={x - 1}
                          y={PAD_T}
                          width={barWidth + 2}
                          height={PLOT_H}
                          fill="none"
                          stroke="currentColor"
                          className="text-primary"
                          strokeWidth={1.5}
                        />
                      )}
                    </g>
                  );
                })}

                {/* Crosshair vertical line */}
                {hoverIdx !== null && (
                  <line
                    x1={PAD_L + ((hoverIdx + 0.5 - viewStart) / span) * PLOT_W}
                    x2={PAD_L + ((hoverIdx + 0.5 - viewStart) / span) * PLOT_W}
                    y1={PAD_T}
                    y2={PAD_T + PLOT_H}
                    stroke="currentColor"
                    className="text-foreground/40"
                    strokeDasharray="2 2"
                    strokeWidth={1}
                  />
                )}
              </g>

              {/* X axis date labels */}
              {xTicks.map((t) => (
                <text
                  key={t.idx}
                  x={t.x}
                  y={CHART_H - 8}
                  textAnchor="middle"
                  className="fill-muted-foreground text-[10px] font-mono"
                >
                  {t.label}
                </text>
              ))}
            </svg>

            {/* Floating interactive tooltip */}
            {hoveredPoint && mousePos && (
              <div
                className="pointer-events-none absolute z-20 rounded-md border border-border bg-popover/95 px-3 py-2 text-xs shadow-lg backdrop-blur-sm min-w-[205px]"
                style={{
                  left: mousePos.x > (containerRef.current?.clientWidth ?? 400) * 0.62 ? undefined : mousePos.x + 14,
                  right:
                    mousePos.x > (containerRef.current?.clientWidth ?? 400) * 0.62
                      ? (containerRef.current?.clientWidth ?? 400) - mousePos.x + 14
                      : undefined,
                  top: Math.max(8, Math.min(mousePos.y - 12, 110)),
                }}
              >
                <div className="font-mono font-semibold text-foreground border-b border-border/60 pb-1 mb-1.5">
                  {formatFullDate(hoveredPoint.date)} ({hoveredPoint.date})
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 font-mono text-[11px]">
                  <span className="text-muted-foreground">Łącznie:</span>
                  <span className="text-right font-semibold text-foreground">
                    {hoveredPoint.total.toLocaleString('pl-PL')}
                  </span>
                  <span className="text-emerald-600 dark:text-emerald-400">Nowe:</span>
                  <span className="text-right">{hoveredPoint.new.toLocaleString('pl-PL')}</span>
                  <span className="text-rose-600 dark:text-rose-400">Offline/Zamk.:</span>
                  <span className="text-right">{hoveredPoint.offline.toLocaleString('pl-PL')}</span>
                  <span className="text-amber-600 dark:text-amber-400">Med/High+:</span>
                  <span className="text-right">{hoveredPoint.high_or_med.toLocaleString('pl-PL')}</span>
                  {(hoveredPoint.tls_changed ?? 0) > 0 && (
                    <>
                      <span className="text-muted-foreground">TLS:</span>
                      <span className="text-right">{hoveredPoint.tls_changed?.toLocaleString('pl-PL')}</span>
                    </>
                  )}
                  {(hoveredPoint.tech_changed ?? 0) > 0 && (
                    <>
                      <span className="text-muted-foreground">Tech:</span>
                      <span className="text-right">{hoveredPoint.tech_changed?.toLocaleString('pl-PL')}</span>
                    </>
                  )}
                </div>
                <div className="mt-1.5 pt-1 border-t border-border/60 text-[10px] text-muted-foreground">
                  Kliknij słupek, aby otworzyć szczegóły dnia
                </div>
              </div>
            )}

            {/* Bottom status bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 px-2 pt-1 text-[10px] font-mono text-muted-foreground">
              <span>
                Zakres: <strong className="text-foreground">{visibleRangeStart}</strong> →{' '}
                <strong className="text-foreground">{visibleRangeEnd}</strong>
              </span>
              <span>Scroll = przybliż/oddal • Przeciągnij = przesuń • Kliknij = szczegóły dnia</span>
            </div>
          </div>
        ) : (
          <div className="h-36 flex items-center justify-center text-xs text-muted-foreground">
            Brak danych osi czasu.
          </div>
        )}

        {/* Selected Day Inspector Panel */}
        {selectedDate && (
          <div className="rounded-md border border-border bg-card p-3.5 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2">
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-primary" />
                <span className="font-mono text-xs font-semibold text-foreground">
                  Szczegóły dnia: {formatFullDate(selectedDate)} ({selectedDate})
                </span>
                {dayDetails && (
                  <Badge variant="secondary" className="font-mono text-[10px]">
                    {dayDetails.total.toLocaleString('pl-PL')} zdarzeń
                  </Badge>
                )}
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setSelectedDate(null)}
                className="h-6 w-6 p-0"
                title="Zamknij szczegóły dnia"
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>

            {dayLoading && (
              <div className="py-4 text-center text-xs font-mono text-muted-foreground">
                Ładowanie rozkładu godzinowego dla {selectedDate}...
              </div>
            )}
            {dayError && <div className="text-xs text-destructive font-mono">{dayError}</div>}

            {!dayLoading && dayDetails && (
              <div className="space-y-3">
                {dayDetails.total === 0 ? (
                  <div className="py-3 text-center text-xs text-muted-foreground font-mono">
                    Brak zarejestrowanych zmian w dniu {selectedDate}.
                  </div>
                ) : (
                  <>
                    {/* 24-hour distribution */}
                    <div>
                      <div className="flex items-center justify-between text-[11px] font-mono text-muted-foreground mb-1.5">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> Rozkład godzinowy (UTC 00:00–23:59)
                        </span>
                        {hoverHour !== null && dayDetails.hourly[hoverHour] && (
                          <span className="text-foreground">
                            {String(hoverHour).padStart(2, '0')}:00–{String(hoverHour).padStart(2, '0')}:59 →{' '}
                            <strong>{dayDetails.hourly[hoverHour].total.toLocaleString('pl-PL')}</strong> (nowe:{' '}
                            {dayDetails.hourly[hoverHour].new}, offline: {dayDetails.hourly[hoverHour].offline})
                          </span>
                        )}
                      </div>
                      <div className="flex items-end gap-1 h-16 px-1 py-1 rounded bg-muted/30 border border-border/50">
                        {(() => {
                          const maxH = Math.max(1, ...dayDetails.hourly.map((h) => h.total));
                          return dayDetails.hourly.map((h) => {
                            const pct = h.total > 0 ? Math.max(10, Math.round((h.total / maxH) * 100)) : 4;
                            return (
                              <div
                                key={h.hour}
                                onMouseEnter={() => setHoverHour(h.hour)}
                                onMouseLeave={() => setHoverHour(null)}
                                className="flex-1 h-full flex flex-col justify-end items-center group cursor-pointer"
                                title={`${String(h.hour).padStart(2, '0')}:00 UTC — ${h.total} zdarzeń`}
                              >
                                <div
                                  className={`w-full rounded-t transition-colors ${
                                    h.total > 0
                                      ? 'bg-primary/80 group-hover:bg-primary'
                                      : 'bg-muted-foreground/20'
                                  }`}
                                  style={{ height: `${pct}%` }}
                                />
                              </div>
                            );
                          });
                        })()}
                      </div>
                      <div className="flex justify-between text-[9px] font-mono text-muted-foreground px-1 mt-0.5">
                        <span>00:00</span>
                        <span>06:00</span>
                        <span>12:00</span>
                        <span>18:00</span>
                        <span>23:00</span>
                      </div>
                    </div>

                    {/* Breakdown by type & severity */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      {dayDetails.by_type.map((t) => (
                        <Badge key={t.change_type} variant="outline" className="font-mono text-[10px] gap-1">
                          <span>{t.change_type}:</span>
                          <strong className="text-foreground">{t.count.toLocaleString('pl-PL')}</strong>
                        </Badge>
                      ))}
                    </div>

                    {/* Sample events from that day */}
                    {dayDetails.sample_events.length > 0 && (
                      <div className="max-h-44 overflow-y-auto rounded border border-border/60 divide-y divide-border/50">
                        {dayDetails.sample_events.map((ev) => (
                          <div
                            key={ev.id}
                            className="flex flex-wrap items-center justify-between gap-2 px-2.5 py-1.5 text-[11px] hover:bg-muted/30"
                          >
                            <div className="flex items-center gap-2 font-mono">
                              <span className="text-muted-foreground">
                                {ev.detected_at.slice(11, 19)} UTC
                              </span>
                              <span className="font-semibold text-foreground">
                                {ev.host_ip ?? '—'}
                                {ev.service_port ? `:${ev.service_port}` : ''}
                              </span>
                              <ChangeTypeBadge type={ev.change_type} />
                            </div>
                            <SeverityBadge severity={ev.severity} />
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
