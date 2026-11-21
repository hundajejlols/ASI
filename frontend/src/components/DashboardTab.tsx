import {
  Activity,
  AlertCircle,
  BarChart3,
  CheckCircle2,
  Clock,
  Download,
  Layers,
  Moon,
  Play,
  Radar,
  Server,
  Shield,
  Sun,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiFetch, downloadExport, hasPermission } from '../api';
import type { ChangeEvent, DashboardSummary, HostSummary, ScanRunInfo, UserRole } from '../types';
import { ChangeTypeBadge, formatTime, HostStatusBadge, SeverityBadge } from './Badges';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
  hosts: HostSummary[];
  changes: ChangeEvent[];
  summary: DashboardSummary | null;
  onRefresh: () => void;
}

export function DashboardTab({ role, hosts, changes, summary, onRefresh }: Props) {
  const [busy, setBusy] = useState(false);
  const [exportingFmt, setExportingFmt] = useState<'json' | 'csv' | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [latestRun, setLatestRun] = useState<ScanRunInfo | null>(null);
  const [groupMode, setGroupMode] = useState<'by_technology' | 'by_product' | 'by_favicon_mmh3'>('by_technology');

  useEffect(() => {
    apiFetch<ScanRunInfo[]>('/scans/runs?limit=1', role)
      .then((runs) => setLatestRun(runs[0] ?? null))
      .catch(() => {});
  }, [role, hosts, changes]);

  // Prawdziwe agregaty serwerowe z /api/v1/dashboard/summary (skaluje się dla >10 000 hostów)
  const totalHosts = summary?.kpi.total_hosts ?? hosts.length;
  const onlineCount = summary?.kpi.online_hosts ?? hosts.filter((h) => h.status === 'online').length;
  const unstableCount = summary?.kpi.unstable_hosts ?? hosts.filter((h) => h.status === 'unstable').length;
  const offlineCount = summary?.kpi.offline_hosts ?? hosts.filter((h) => h.status === 'offline').length;
  const totalServices = summary?.kpi.total_open_services ?? hosts.reduce((acc, h) => acc + h.open_services_count, 0);
  const totalChanges = summary?.kpi.total_changes ?? changes.length;
  const sigMatchesCount =
    summary?.kpi.active_signature_matches ?? hosts.reduce((acc, h) => acc + (h.signature_matches_count ?? 0), 0);

  const topFindingsHosts = [...hosts]
    .filter(
      (h) =>
        !h.override?.is_ignored &&
        (h.is_admin_panel ||
          h.is_staging_env ||
          (h.signature_matches_count ?? 0) > 0 ||
          (h.priority_score ?? 0) > 0)
    )
    .sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0));

  const timeline = summary?.changes_timeline ?? [];
  const maxTimelineVal = Math.max(1, ...timeline.map((d) => d.total));
  const activeGroups = summary?.service_groups?.[groupMode] ?? [];
  const dayStats = summary?.time_of_day_analysis.day_06_22;
  const nightStats = summary?.time_of_day_analysis.night_22_06;

  const canStartScan = hasPermission(role, 'add');

  async function handleQuickScan() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await apiFetch<{ scan_run_id: string; total_chunks: number; active_signatures_count: number }>(
        '/scans/start',
        role,
        {
          method: 'POST',
          body: JSON.stringify({ window_minutes: 30, dry_run: false }),
        }
      );
      setNotice(
        `Uruchomiono skan (${res.scan_run_id.slice(0, 8)}...) — paczek: ${res.total_chunks}, sygnatur: ${res.active_signatures_count}.`
      );
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd uruchamiania skanu');
    } finally {
      setBusy(false);
    }
  }

  async function handleExport(fmt: 'json' | 'csv') {
    setError(null);
    setNotice(null);
    setExportingFmt(fmt);
    try {
      await downloadExport(fmt, role);
      setNotice(`Wyeksportowano asi_export.${fmt}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd eksportu');
    } finally {
      setExportingFmt(null);
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          {latestRun && (
            <Badge variant="secondary" className="font-mono gap-1.5">
              <Clock className="h-3 w-3" />
              <span>
                Ostatni skan ({latestRun.id.slice(0, 8)}): {latestRun.status} • paczki{' '}
                {latestRun.completed_chunks}/{latestRun.total_chunks}
                {typeof latestRun.duration_seconds === 'number' ? ` • ${latestRun.duration_seconds}s` : ''}
              </span>
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {canStartScan && (
            <Button size="sm" onClick={handleQuickScan} disabled={busy}>
              <Play className="h-3.5 w-3.5" />
              {busy ? 'Uruchamianie...' : 'Uruchom skan'}
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleExport('json')}
            disabled={exportingFmt !== null}
          >
            <Download className="h-3.5 w-3.5" />
            {exportingFmt === 'json' ? '...' : 'JSON'}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleExport('csv')}
            disabled={exportingFmt !== null}
          >
            <Download className="h-3.5 w-3.5" />
            {exportingFmt === 'csv' ? '...' : 'CSV'}
          </Button>
        </div>
      </div>

      {notice && (
        <Alert>
          <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
          <AlertDescription className="text-foreground">{notice}</AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <AlertDescription className="text-foreground">{error}</AlertDescription>
        </Alert>
      )}

      {/* Karty KPI (prawdziwe agregaty serwerowe SQL) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">Hosty</CardDescription>
            <Server className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{totalHosts}</div>
            <div className="mt-0.5 flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground">
              <span>{onlineCount} on</span>
              <span>/</span>
              <span>{unstableCount} un</span>
              <span>/</span>
              <span>{offlineCount} off</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">Usługi otwarte</CardDescription>
            <Radar className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{totalServices}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">Zmiany (Diff)</CardDescription>
            <Activity className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{totalChanges}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">Trafienia sygnatur</CardDescription>
            <Shield className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{sigMatchesCount}</div>
          </CardContent>
        </Card>
      </div>

      {/* Wizualizacja zmian w czasie + Pora dnia (Dzień vs Noc) + Grupowanie usług */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader className="px-4 py-3 border-b border-border flex-row items-center justify-between space-y-0">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <BarChart3 className="h-3.5 w-3.5" />
              Wizualizacja zmian w czasie &amp; Pora dnia (14 dni)
            </CardTitle>
            {dayStats && nightStats && (
              <div className="flex items-center gap-3 text-[11px] font-mono text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Sun className="h-3 w-3" /> Dzień (06–22): <strong className="text-foreground">{dayStats.total}</strong>
                </span>
                <span className="flex items-center gap-1">
                  <Moon className="h-3 w-3" /> Noc (22–06): <strong className="text-foreground">{nightStats.total}</strong>
                </span>
              </div>
            )}
          </CardHeader>
          <CardContent className="p-4">
            {timeline.length > 0 ? (
              <div className="flex items-end gap-2 h-32 pt-4">
                {timeline.map((bucket) => {
                  const pct = Math.max(8, Math.round((bucket.total / maxTimelineVal) * 100));
                  const highPct = bucket.total > 0 ? Math.round((bucket.high_or_med / bucket.total) * 100) : 0;
                  return (
                    <div key={bucket.date} className="flex-1 flex flex-col items-center gap-1 min-w-[36px]">
                      <span className="text-[10px] font-mono text-muted-foreground">{bucket.total}</span>
                      <div
                        className="w-full max-w-[34px] rounded-t bg-primary/80 relative overflow-hidden transition-all"
                        style={{ height: `${pct}%` }}
                        title={`${bucket.date}: łącznie ${bucket.total} (nowe: ${bucket.new}, offline: ${bucket.offline}, med/high: ${bucket.high_or_med})`}
                      >
                        {highPct > 0 && (
                          <div
                            className="absolute bottom-0 inset-x-0 bg-amber-500/80"
                            style={{ height: `${highPct}%` }}
                          />
                        )}
                      </div>
                      <span className="text-[10px] font-mono text-muted-foreground truncate">
                        {bucket.date.slice(5)}
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="h-28 flex items-center justify-center text-xs text-muted-foreground">
                Brak zdarzeń w ostatnich 14 dniach.
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="px-4 py-3 border-b border-border space-y-2">
            <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5" />
              Grupowanie podobnych usług
            </CardTitle>
            <div className="flex gap-1">
              {(
                [
                  ['by_technology', 'Tech'],
                  ['by_product', 'Produkt'],
                  ['by_favicon_mmh3', 'Favicon'],
                ] as const
              ).map(([k, lbl]) => (
                <Button
                  key={k}
                  size="sm"
                  variant={groupMode === k ? 'default' : 'outline'}
                  onClick={() => setGroupMode(k)}
                  className="h-6 px-2 text-[10px] font-mono"
                >
                  {lbl}
                </Button>
              ))}
            </div>
          </CardHeader>
          <CardContent className="p-3 space-y-2 max-h-40 overflow-y-auto">
            {activeGroups.map((g) => (
              <div key={g.key} className="flex items-center justify-between gap-2 text-xs">
                <div className="truncate">
                  <span className="font-mono font-medium text-foreground">{g.key}</span>
                  <span className="ml-1.5 text-[10px] font-mono text-muted-foreground">
                    ({g.sample_endpoints.slice(0, 2).join(', ')})
                  </span>
                </div>
                <Badge variant="secondary" className="font-mono shrink-0">
                  {g.count}
                </Badge>
              </div>
            ))}
            {activeGroups.length === 0 && (
              <div className="py-6 text-center text-xs text-muted-foreground">Brak grup usług.</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Najważniejsze znaleziska i hosty wysokiego priorytetu analitycznego */}
      <Card>
        <CardHeader className="px-4 py-3 border-b border-border flex-row items-center justify-between space-y-0">
          <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
            Najważniejsze znaleziska (Priorytet analityczny)
          </CardTitle>
          <span className="text-[11px] font-mono text-muted-foreground">
            {topFindingsHosts.length} zasobów wymagających uwagi
          </span>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Klasyfikacja / Środowisko</TableHead>
                <TableHead>Wykryte technologie</TableHead>
                <TableHead>Sygnatury</TableHead>
                <TableHead>Severity / Priorytet</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {topFindingsHosts.map((h) => (
                <TableRow key={h.id}>
                  <TableCell>
                    <div className="font-mono font-semibold text-foreground">{h.ip_address}</div>
                    <div className="text-[11px] text-muted-foreground">
                      {h.override?.custom_label || h.hostname || '—'}
                    </div>
                  </TableCell>
                  <TableCell>
                    <HostStatusBadge status={h.status} missedScans={h.missed_scans} />
                  </TableCell>
                  <TableCell className="space-x-1">
                    {h.is_admin_panel && (
                      <Badge variant="default" className="font-mono uppercase text-[10px]">
                        ADMIN PANEL
                      </Badge>
                    )}
                    {h.is_staging_env && (
                      <Badge variant="outline" className="font-mono uppercase text-[10px]">
                        STAGING / DEV
                      </Badge>
                    )}
                    {!h.is_admin_panel && !h.is_staging_env && (
                      <span className="text-xs text-muted-foreground">Usługa standardowa</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(h.technologies || []).map((t) => (
                        <Badge key={t} variant="secondary" className="font-mono text-[10px]">
                          {t}
                        </Badge>
                      ))}
                      {(h.technologies || []).length === 0 && (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono">
                    {h.signature_matches_count ?? 0}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={h.highest_severity || 'info'} />
                      <span className="font-mono text-[11px] text-muted-foreground">
                        {h.priority_score ?? 0}/100
                      </span>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {topFindingsHosts.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                    Brak znalezisk wysokiego priorytetu. Uruchom skan, aby wykryć usługi.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Ostatnie zdarzenia Diff */}
      <Card>
        <CardHeader className="px-4 py-3 border-b border-border">
          <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
            Ostatnie zmiany (Diff)
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Czas</TableHead>
                <TableHead>Typ</TableHead>
                <TableHead>Host / Port</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Szczegóły</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {changes.slice(0, 10).map((ch) => (
                <TableRow key={ch.id}>
                  <TableCell className="text-muted-foreground font-mono whitespace-nowrap">
                    {formatTime(ch.detected_at)}
                  </TableCell>
                  <TableCell>
                    <ChangeTypeBadge type={ch.change_type} />
                  </TableCell>
                  <TableCell className="font-mono">
                    {ch.host_ip || ch.host_id.slice(0, 8)}
                    {ch.service_port ? `:${ch.service_port}/${ch.service_protocol}` : ''}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={ch.severity} />
                  </TableCell>
                  <TableCell className="font-mono text-muted-foreground max-w-md truncate">
                    {ch.current_value ? JSON.stringify(ch.current_value) : '—'}
                  </TableCell>
                </TableRow>
              ))}
              {changes.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                    Brak zmian.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
