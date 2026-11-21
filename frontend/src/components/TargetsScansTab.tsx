import {
  AlertCircle,
  CalendarClock,
  CheckCircle2,
  Clock,
  Download,
  Edit3,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Trash2,
  Upload,
  X,
  XCircle,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { apiFetch, downloadExport, hasPermission } from '../api';
import type { ScanRunInfo, ScheduleItem, TargetItem, UserRole } from '../types';
import { formatTime } from './Badges';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Checkbox, Switch } from './ui/checkbox';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
  onRefreshAll: () => void;
}

interface ScanProfileOption {
  id: string;
  name: string;
  ports: string;
  rate_limit_pps: number;
  chunk_cidr_prefix: number;
}

export function TargetsScansTab({ role, onRefreshAll }: Props) {
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [profiles, setProfiles] = useState<ScanProfileOption[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [newTarget, setNewTarget] = useState('');
  const [chunkPrefix, setChunkPrefix] = useState(24);
  const [adaptiveChunking, setAdaptiveChunking] = useState(true);
  const [rateLimitPps, setRateLimitPps] = useState(250);
  const [windowMinutes, setWindowMinutes] = useState(45);
  const [ports, setPorts] = useState('80,443,8080,8443,22');
  const [customTargetsText, setCustomTargetsText] = useState('');
  const [dryRun, setDryRun] = useState(true);

  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null);
  const [scanRuns, setScanRuns] = useState<ScanRunInfo[]>([]);
  const [schedules, setSchedules] = useState<ScheduleItem[]>([]);
  const [editingSchedId, setEditingSchedId] = useState<string | null>(null);
  const [schedName, setSchedName] = useState('');
  const [schedCron, setSchedCron] = useState('0 22 * * *');
  const [schedWinStart, setSchedWinStart] = useState('22:00');
  const [schedWinEnd, setSchedWinEnd] = useState('06:00');
  const [schedThreshold, setSchedThreshold] = useState(3);
  const [savingSched, setSavingSched] = useState(false);

  // Ręczne dodawanie obserwacji/wyniku (ten sam ingest pipeline co skaner i CSV/JSON)
  const [showManualForm, setShowManualForm] = useState(false);
  const [manIp, setManIp] = useState('');
  const [manHostname, setManHostname] = useState('');
  const [manPort, setManPort] = useState('80');
  const [manProto, setManProto] = useState<'tcp' | 'udp'>('tcp');
  const [manService, setManService] = useState('http');
  const [manProduct, setManProduct] = useState('');
  const [manVersion, setManVersion] = useState('');
  const [manBanner, setManBanner] = useState('');
  const [manUrl, setManUrl] = useState('');
  const [manHttpStatus, setManHttpStatus] = useState('200');
  const [manTitle, setManTitle] = useState('');
  const [manHeaders, setManHeaders] = useState('');
  const [manCookies, setManCookies] = useState('');
  const [manFavicon, setManFavicon] = useState('');
  const [manTechs, setManTechs] = useState('');
  const [manIsAdmin, setManIsAdmin] = useState(false);
  const [manIsStaging, setManIsStaging] = useState(false);
  const [submittingManual, setSubmittingManual] = useState(false);

  const [resumingRunId, setResumingRunId] = useState<string | null>(null);
  const [cancellingRunId, setCancellingRunId] = useState<string | null>(null);
  const [reprobingUnstable, setReprobingUnstable] = useState(false);
  const [importResult, setImportResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [addingTarget, setAddingTarget] = useState(false);
  const [exportingFmt, setExportingFmt] = useState<'json' | 'csv' | null>(null);

  const targetsFileRef = useRef<HTMLInputElement>(null);
  const resultsFileRef = useRef<HTMLInputElement>(null);

  const canAdd = hasPermission(role, 'add');
  const canModify = hasPermission(role, 'modify');
  const canDelete = hasPermission(role, 'delete');

  async function loadTargets() {
    try {
      const data = await apiFetch<TargetItem[]>('/targets', role);
      setTargets(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania celów');
    }
  }

  async function loadScanRuns() {
    try {
      const runs = await apiFetch<ScanRunInfo[]>('/scans/runs?limit=8', role);
      setScanRuns(runs);
    } catch {
      // ignore background poll errors
    }
  }

  async function loadSchedules() {
    try {
      const data = await apiFetch<ScheduleItem[]>('/schedules', role);
      setSchedules(data);
    } catch {
      // ignore background load errors
    }
  }

  async function loadProfiles() {
    try {
      const data = await apiFetch<ScanProfileOption[]>('/scans/profiles', role);
      setProfiles(data);
    } catch {
      // ignore background load errors
    }
  }

  useEffect(() => {
    loadTargets();
    loadScanRuns();
    loadSchedules();
    loadProfiles();
  }, [role]);

  useEffect(() => {
    const hasActiveRun = scanRuns.some((r) => r.status === 'queued' || r.status === 'running');
    if (!hasActiveRun) return;
    const timer = setInterval(async () => {
      try {
        const runs = await apiFetch<ScanRunInfo[]>('/scans/runs?limit=8', role);
        setScanRuns(runs);
        const stillActive = runs.some((r) => r.status === 'queued' || r.status === 'running');
        if (!stillActive) {
          onRefreshAll();
        }
      } catch {
        // ignore poll error
      }
    }, 2500);
    return () => clearInterval(timer);
  }, [scanRuns, role, onRefreshAll]);

  async function handleAddTarget(e: React.FormEvent) {
    e.preventDefault();
    if (!newTarget.trim() || !canAdd) return;
    setError(null);
    setImportResult(null);
    setAddingTarget(true);
    try {
      await apiFetch('/targets', role, {
        method: 'POST',
        body: JSON.stringify({ raw_value: newTarget.trim() }),
      });
      setImportResult(`Dodano cel: ${newTarget.trim()}`);
      setNewTarget('');
      await loadTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd dodawania celu');
    } finally {
      setAddingTarget(false);
    }
  }

  async function handleDeleteTarget(id: string) {
    if (!canDelete) return;
    setError(null);
    try {
      await apiFetch(`/targets/${id}`, role, { method: 'DELETE' });
      await loadTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania celu');
    }
  }

  async function handleUploadTargets(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !canAdd) return;
    setError(null);
    setImportResult(null);
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await apiFetch<{ added: number; skipped_duplicates: number; errors: string[] }>(
        '/targets/import',
        role,
        { method: 'POST', body: fd }
      );
      if (res.errors && res.errors.length > 0) {
        setError(
          `Odrzucono ${res.errors.length} nieprawidłowych wpisów: ${res.errors.slice(0, 3).join('; ')}${
            res.errors.length > 3 ? '...' : ''
          }`
        );
      }
      setImportResult(
        `Zaimportowano cele: dodano ${res.added}, pominięto duplikatów: ${res.skipped_duplicates}, błędów: ${res.errors?.length ?? 0}.`
      );
      await loadTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd importu celów');
    } finally {
      e.target.value = '';
    }
  }

  async function handleStartScan(e: React.FormEvent) {
    e.preventDefault();
    if (!canAdd) return;
    setBusy(true);
    setError(null);
    setScanResult(null);
    try {
      const rawTargets = customTargetsText
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const body: Record<string, unknown> = {
        chunk_cidr_prefix: adaptiveChunking ? null : chunkPrefix,
        adaptive_chunking: adaptiveChunking,
        rate_limit_pps: rateLimitPps,
        window_minutes: windowMinutes,
        dry_run: dryRun,
      };
      if (selectedProfileId) {
        body.profile_id = selectedProfileId;
      }
      if (ports.trim()) {
        body.ports = ports.trim();
      }
      if (rawTargets.length > 0) {
        body.raw_targets = rawTargets;
      }
      const res = await apiFetch<Record<string, unknown>>('/scans/start', role, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      setScanResult(res);
      if (!dryRun) {
        await loadScanRuns();
        onRefreshAll();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd uruchamiania skanu');
    } finally {
      setBusy(false);
    }
  }

  async function handleResumeScanRun(runId: string) {
    if (!canAdd) return;
    setResumingRunId(runId);
    setError(null);
    setImportResult(null);
    try {
      const res = await apiFetch<{ requeued_chunks: number }>(`/scans/${runId}/resume`, role, {
        method: 'POST',
        body: JSON.stringify({
          window_minutes: windowMinutes,
          rate_limit_pps: rateLimitPps,
          ports: ports.trim() || undefined,
        }),
      });
      setImportResult(
        `Wznowiono skan ${runId.slice(0, 8)}... w nowym oknie czasowym (ponownie zakolejkowano paczek: ${res.requeued_chunks}).`
      );
      await loadScanRuns();
      onRefreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd wznawiania skanu');
    } finally {
      setResumingRunId(null);
    }
  }

  async function handleCancelScanRun(runId: string) {
    if (!canAdd) return;
    setCancellingRunId(runId);
    setError(null);
    try {
      await apiFetch(`/scans/${runId}/cancel`, role, { method: 'POST' });
      setImportResult(`Anulowano przebieg skanu ${runId.slice(0, 8)}...`);
      await loadScanRuns();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd anulowania skanu');
    } finally {
      setCancellingRunId(null);
    }
  }

  async function handleReprobeUnstable() {
    if (!canAdd) return;
    setReprobingUnstable(true);
    setError(null);
    setImportResult(null);
    try {
      const res = await apiFetch<{ queued: boolean; unstable_hosts_count: number; message?: string }>(
        '/scans/reprobe-unstable',
        role,
        { method: 'POST' }
      );
      if (res.queued) {
        setImportResult(`Zakolejkowano ponowny pomiar dla ${res.unstable_hosts_count} niestabilnych hostów.`);
        await loadScanRuns();
      } else {
        setImportResult(res.message || 'Brak niestabilnych hostów.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd uruchamiania powtórnego pomiaru');
    } finally {
      setReprobingUnstable(false);
    }
  }

  function startEditSchedule(s: ScheduleItem) {
    setEditingSchedId(s.id);
    setSchedName(s.name);
    setSchedCron(s.cron_expression);
    setSchedWinStart(s.window_start);
    setSchedWinEnd(s.window_end);
    setSchedThreshold(s.missed_scans_threshold);
  }

  function resetScheduleForm() {
    setEditingSchedId(null);
    setSchedName('');
    setSchedCron('0 22 * * *');
    setSchedWinStart('22:00');
    setSchedWinEnd('06:00');
    setSchedThreshold(3);
  }

  async function handleCreateSchedule(e: React.FormEvent) {
    e.preventDefault();
    if (!schedName.trim()) return;
    if (editingSchedId ? !canModify : !canAdd) return;
    setSavingSched(true);
    setError(null);
    setImportResult(null);
    try {
      const payload = {
        name: schedName.trim(),
        cron_expression: schedCron.trim(),
        window_start: schedWinStart,
        window_end: schedWinEnd,
        timezone: 'Europe/Warsaw',
        missed_scans_threshold: schedThreshold,
      };
      if (editingSchedId) {
        await apiFetch(`/schedules/${editingSchedId}`, role, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        });
        setImportResult(`Zaktualizowano harmonogram "${schedName.trim()}".`);
      } else {
        await apiFetch('/schedules', role, {
          method: 'POST',
          body: JSON.stringify({ ...payload, is_enabled: true }),
        });
        setImportResult(`Dodano harmonogram cykliczny "${schedName.trim()}" (${schedWinStart}–${schedWinEnd}).`);
      }
      resetScheduleForm();
      await loadSchedules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu harmonogramu');
    } finally {
      setSavingSched(false);
    }
  }

  async function handleToggleSchedule(s: ScheduleItem) {
    if (!canModify) return;
    setError(null);
    try {
      await apiFetch(`/schedules/${s.id}`, role, {
        method: 'PATCH',
        body: JSON.stringify({ is_enabled: !s.is_enabled }),
      });
      await loadSchedules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zmiany statusu harmonogramu');
    }
  }

  async function handleDeleteSchedule(id: string) {
    if (!canDelete) return;
    setError(null);
    try {
      await apiFetch(`/schedules/${id}`, role, { method: 'DELETE' });
      await loadSchedules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania harmonogramu');
    }
  }

  async function handleSubmitManualFinding(e: React.FormEvent) {
    e.preventDefault();
    if (!canAdd || !manIp.trim()) return;
    setSubmittingManual(true);
    setError(null);
    setImportResult(null);
    try {
      const techs = manTechs
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      const cookiesList = manCookies
        .split(',')
        .map((c) => c.trim())
        .filter(Boolean);
      const headersObj: Record<string, string> = {};
      for (const line of manHeaders.split('\n')) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          const k = line.slice(0, idx).trim();
          const v = line.slice(idx + 1).trim();
          if (k) headersObj[k] = v;
        }
      }
      const res = await apiFetch<{ hosts_processed: number; changes_recorded: number }>('/scans/manual', role, {
        method: 'POST',
        body: JSON.stringify({
          ip_address: manIp.trim(),
          hostname: manHostname.trim() || null,
          port: Number(manPort),
          protocol: manProto,
          service_name: manService.trim() || null,
          product: manProduct.trim() || null,
          version: manVersion.trim() || null,
          banner: manBanner.trim() || null,
          http_url: manUrl.trim() || null,
          http_status: manHttpStatus ? Number(manHttpStatus) : null,
          http_title: manTitle.trim() || null,
          headers: headersObj,
          cookies: cookiesList,
          favicon_mmh3_hash: manFavicon.trim() || null,
          technologies: techs,
          is_admin_panel: manIsAdmin,
          is_staging_env: manIsStaging,
        }),
      });
      setImportResult(
        `Zapisano ręczną obserwację dla ${manIp.trim()}:${manPort} przez ingest pipeline (nowych zmian Diff: ${res.changes_recorded}).`
      );
      setManIp('');
      setManHostname('');
      setManProduct('');
      setManVersion('');
      setManBanner('');
      setManUrl('');
      setManTitle('');
      setManHeaders('');
      setManCookies('');
      setManFavicon('');
      setManTechs('');
      setManIsAdmin(false);
      setManIsStaging(false);
      onRefreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu ręcznej obserwacji');
    } finally {
      setSubmittingManual(false);
    }
  }

  async function handleImportScanResults(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !canAdd) return;
    setError(null);
    setImportResult(null);
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await apiFetch<{ hosts_processed: number; changes_recorded: number }>(
        '/scans/import',
        role,
        { method: 'POST', body: fd }
      );
      setImportResult(
        `Zaimportowano wyniki skanu przez ingest pipeline: hostów=${res.hosts_processed}, nowych zmian Diff=${res.changes_recorded}.`
      );
      onRefreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd importu wyników');
    } finally {
      e.target.value = '';
    }
  }

  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <AlertDescription className="text-foreground">{error}</AlertDescription>
        </Alert>
      )}
      {importResult && (
        <Alert>
          <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
          <AlertDescription className="text-foreground">{importResult}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Lewa kolumna: Zarządzanie celami */}
        <Card>
          <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
            <CardTitle>Cele ({targets.length})</CardTitle>
            {canAdd && (
              <>
                <input
                  ref={targetsFileRef}
                  type="file"
                  accept=".csv,.json"
                  onChange={handleUploadTargets}
                  className="hidden"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => targetsFileRef.current?.click()}
                >
                  <Upload className="h-3.5 w-3.5" />
                  Import (CSV / JSON)
                </Button>
              </>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {canAdd && (
              <form onSubmit={handleAddTarget} className="flex gap-2">
                <Input
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  placeholder="np. 172.28.0.0/22, 10.0.0.1 lub web.agh.edu.pl"
                  className="flex-1 font-mono"
                />
                <Button type="submit" disabled={addingTarget}>
                  <Plus className="h-3.5 w-3.5" />
                  {addingTarget ? 'Dodawanie...' : 'Dodaj cel'}
                </Button>
              </form>
            )}

            <div className="rounded-md border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Typ</TableHead>
                    <TableHead>Wartość</TableHead>
                    <TableHead>Dodano</TableHead>
                    {canDelete && <TableHead className="text-right">Akcja</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {targets.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell>
                        <Badge variant="secondary" className="uppercase font-mono text-[10px]">
                          {t.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono font-medium">{t.raw_value}</TableCell>
                      <TableCell className="text-muted-foreground font-mono text-[11px]">
                        {formatTime(t.created_at)}
                      </TableCell>
                      {canDelete && (
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteTarget(t.id)}
                            className="h-7 px-2"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                            Usuń
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                  {targets.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={canDelete ? 4 : 3} className="py-6 text-center text-muted-foreground">
                        Brak zapisanych celów.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Prawa kolumna: Orkiestrator skanowania (Chunker CIDR & Okna czasowe) */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle>Skanowanie &amp; Chunker CIDR</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handleStartScan} className="space-y-3 text-xs">
              {profiles.length > 0 && (
                <label className="block space-y-1">
                  <span className="text-muted-foreground">Profil skanowania (preset portów i limitów)</span>
                  <Select
                    disabled={!canAdd}
                    value={selectedProfileId}
                    onChange={(e) => {
                      const pid = e.target.value;
                      setSelectedProfileId(pid);
                      const found = profiles.find((p) => p.id === pid);
                      if (found) {
                        setPorts(found.ports);
                        setRateLimitPps(found.rate_limit_pps);
                        setChunkPrefix(found.chunk_cidr_prefix);
                      }
                    }}
                    className="font-mono"
                  >
                    <option value="">Domyślny (default-safe-lab)</option>
                    {profiles.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} — {p.ports.length > 42 ? `${p.ports.slice(0, 42)}…` : p.ports}
                      </option>
                    ))}
                  </Select>
                </label>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="block space-y-1">
                  <span className="text-muted-foreground">Cele ad-hoc (opcjonalnie)</span>
                  <Input
                    disabled={!canAdd}
                    value={customTargetsText}
                    onChange={(e) => setCustomTargetsText(e.target.value)}
                    placeholder="np. 172.28.0.0/22"
                    className="font-mono"
                  />
                </label>

                <label className="block space-y-1">
                  <span className="text-muted-foreground">Dozwolone porty (nmap -p / top-1000)</span>
                  <Input
                    disabled={!canAdd}
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    placeholder="np. 80,443,8080,8443,22 lub top-1000"
                    className="font-mono"
                  />
                </label>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">Maska paczki (CIDR)</span>
                  <Input
                    type="number"
                    min={16}
                    max={32}
                    disabled={!canAdd}
                    value={chunkPrefix}
                    onChange={(e) => setChunkPrefix(Number(e.target.value))}
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Rate-limit (pps)</span>
                  <Input
                    type="number"
                    min={10}
                    disabled={!canAdd}
                    value={rateLimitPps}
                    onChange={(e) => setRateLimitPps(Number(e.target.value))}
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Okno (minuty)</span>
                  <Input
                    type="number"
                    min={1}
                    max={1440}
                    disabled={!canAdd}
                    value={windowMinutes}
                    onChange={(e) => setWindowMinutes(Number(e.target.value))}
                    className="font-mono"
                  />
                </label>
              </div>

              <div className="space-y-2 pt-1 text-foreground">
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    disabled={!canAdd}
                    checked={adaptiveChunking}
                    onCheckedChange={(v) => setAdaptiveChunking(Boolean(v))}
                  />
                  <span>Adaptacyjny podział paczek (dobór maski /24–/28 wg szybkości skanowania i okna + ETA)</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    disabled={!canAdd}
                    checked={dryRun}
                    onCheckedChange={(v) => setDryRun(Boolean(v))}
                  />
                  <span>Tryb Dry-Run (podgląd wygenerowanych paczek CIDR i ETA bez kolejkowania w Redis)</span>
                </label>
              </div>

              {canAdd ? (
                <Button type="submit" disabled={busy} className="mt-1">
                  <Play className="h-3.5 w-3.5" />
                  {busy ? 'Przetwarzanie...' : dryRun ? 'Podgląd paczek (Dry-Run)' : 'Uruchom skan'}
                </Button>
              ) : (
                <p className="text-muted-foreground">
                  Uruchamianie skanów wymaga roli <code className="font-mono">add_delete_modify</code> lub{' '}
                  <code className="font-mono">admin</code>.
                </p>
              )}
            </form>

            {scanResult && (
              <pre className="p-3 rounded-md bg-muted border border-border text-[11px] font-mono text-foreground overflow-x-auto max-h-56">
                {JSON.stringify(scanResult, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Harmonogramy cyklicznych skanów i okna czasowe (HH:MM-HH:MM + auto-resume) */}
      <Card>
        <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-sm">
            <CalendarClock className="h-4 w-4 text-muted-foreground" />
            Harmonogramy cyklicznych skanów &amp; Okna czasowe ({schedules.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {(editingSchedId ? canModify : canAdd) && (
            <form onSubmit={handleCreateSchedule} className="grid grid-cols-1 md:grid-cols-6 gap-2.5 text-xs items-end">
              <label className="space-y-1 md:col-span-2">
                <span className="text-muted-foreground">
                  {editingSchedId ? 'Edycja harmonogramu' : 'Nazwa harmonogramu'}
                </span>
                <Input
                  required
                  value={schedName}
                  onChange={(e) => setSchedName(e.target.value)}
                  placeholder="np. Nocny skan kampusu AGH"
                />
              </label>
              <label className="space-y-1">
                <span className="text-muted-foreground">Częstotliwość (cron)</span>
                <Input
                  required
                  value={schedCron}
                  onChange={(e) => setSchedCron(e.target.value)}
                  placeholder="0 22 * * *"
                  className="font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-muted-foreground">Okno od – do</span>
                <div className="flex items-center gap-1">
                  <Input
                    type="time"
                    value={schedWinStart}
                    onChange={(e) => setSchedWinStart(e.target.value)}
                    className="font-mono px-2"
                  />
                  <Input
                    type="time"
                    value={schedWinEnd}
                    onChange={(e) => setSchedWinEnd(e.target.value)}
                    className="font-mono px-2"
                  />
                </div>
              </label>
              <label className="space-y-1">
                <span className="text-muted-foreground">Próg missed</span>
                <Input
                  type="number"
                  min={1}
                  max={20}
                  value={schedThreshold}
                  onChange={(e) => setSchedThreshold(Number(e.target.value))}
                  className="font-mono"
                />
              </label>
              <div className="flex gap-1.5">
                <Button type="submit" disabled={savingSched} className="flex-1">
                  {editingSchedId ? <Edit3 className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
                  {savingSched ? 'Zapis...' : editingSchedId ? 'Zapisz' : 'Dodaj'}
                </Button>
                {editingSchedId && (
                  <Button type="button" variant="outline" size="icon" onClick={resetScheduleForm} title="Anuluj edycję">
                    <X className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            </form>
          )}

          <div className="rounded-md border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Nazwa</TableHead>
                  <TableHead>Cron</TableHead>
                  <TableHead>Okno czasowe</TableHead>
                  <TableHead>Próg missed</TableHead>
                  <TableHead>Status</TableHead>
                  {(canModify || canDelete) && <TableHead className="text-right">Akcja</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-medium text-foreground">{s.name}</TableCell>
                    <TableCell className="font-mono text-xs">{s.cron_expression}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {s.window_start}–{s.window_end} ({s.timezone}){' '}
                      <Badge variant={s.in_window_now ? 'default' : 'outline'} className="ml-1 font-mono text-[10px]">
                        {s.in_window_now ? `w oknie (${s.remaining_window_minutes}m)` : 'poza oknem'}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{s.missed_scans_threshold}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {canModify && (
                          <Switch checked={s.is_enabled} onCheckedChange={() => handleToggleSchedule(s)} />
                        )}
                        <Badge variant={s.is_enabled ? 'default' : 'outline'} className="font-mono text-[10px]">
                          {s.is_enabled ? 'aktywny' : 'wyłączony'}
                        </Badge>
                      </div>
                    </TableCell>
                    {(canModify || canDelete) && (
                      <TableCell className="text-right whitespace-nowrap space-x-1">
                        {canModify && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => startEditSchedule(s)}
                            className="h-7 px-2"
                          >
                            <Edit3 className="h-3.5 w-3.5" />
                            Edytuj
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteSchedule(s.id)}
                            className="h-7 px-2"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                            Usuń
                          </Button>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                ))}
                {schedules.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={canModify || canDelete ? 6 : 5} className="py-5 text-center text-muted-foreground">
                      Brak zdefiniowanych harmonogramów cyklicznych.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Historia przebiegów skanów, czas trwania (duration_seconds) i wznawianie po oknie czasowym */}
      <Card>
        <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Clock className="h-4 w-4 text-muted-foreground" />
            Przebiegi skanów — Czas trwania &amp; Okna czasowe ({scanRuns.length})
          </CardTitle>
          {canAdd && (
            <Button size="sm" variant="outline" disabled={reprobingUnstable} onClick={handleReprobeUnstable}>
              <RefreshCw className="h-3.5 w-3.5" />
              {reprobingUnstable ? 'Kolejkowanie...' : 'Powtórz pomiar (niestabilne)'}
            </Button>
          )}
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID Skanu</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Postęp paczek</TableHead>
                <TableHead>Czas trwania</TableHead>
                <TableHead>Rozpoczęto</TableHead>
                <TableHead>Koniec okna</TableHead>
                {canAdd && <TableHead className="text-right">Akcja</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {scanRuns.map((run) => {
                const canResume =
                  canAdd && (run.status === 'paused_window' || run.status === 'failed');
                const canCancel =
                  canAdd && (run.status === 'queued' || run.status === 'running' || run.status === 'paused_window');
                return (
                  <TableRow key={run.id}>
                    <TableCell className="font-mono text-xs">{run.id.slice(0, 8)}...</TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          run.status === 'completed'
                            ? 'default'
                            : run.status === 'paused_window'
                            ? 'secondary'
                            : 'outline'
                        }
                        className="font-mono"
                      >
                        {run.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {run.completed_chunks} / {run.total_chunks}
                    </TableCell>
                    <TableCell className="font-mono text-xs font-semibold">
                      {typeof run.duration_seconds === 'number' ? `${run.duration_seconds} s` : '—'}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatTime(run.started_at || run.created_at)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatTime(run.window_deadline_at)}
                    </TableCell>
                    {canAdd && (
                      <TableCell className="text-right whitespace-nowrap space-x-1">
                        {canResume && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={resumingRunId === run.id}
                            onClick={() => handleResumeScanRun(run.id)}
                            className="h-7 px-2 text-xs"
                          >
                            <RotateCcw className="h-3 w-3" />
                            {resumingRunId === run.id ? 'Wznawianie...' : 'Wznów'}
                          </Button>
                        )}
                        {canCancel && (
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={cancellingRunId === run.id}
                            onClick={() => handleCancelScanRun(run.id)}
                            className="h-7 px-2 text-xs"
                          >
                            <XCircle className="h-3 w-3" />
                            Anuluj
                          </Button>
                        )}
                        {!canResume && !canCancel && <span className="text-xs text-muted-foreground">—</span>}
                      </TableCell>
                    )}
                  </TableRow>
                );
              })}
              {scanRuns.length === 0 && (
                <TableRow>
                  <TableCell colSpan={canAdd ? 7 : 6} className="py-6 text-center text-muted-foreground">
                    Brak zarejestrowanych przebiegów skanu.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Dolny panel: Ręczne dodanie wyniku + Import / Eksport wyników */}
      <Card>
        <CardContent className="p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <h3 className="text-sm font-semibold text-foreground">Wprowadzanie ręczne &amp; Import / Eksport wyników</h3>
            <div className="flex flex-wrap items-center gap-2">
              {canAdd && (
                <>
                  <Button
                    variant={showManualForm ? 'default' : 'outline'}
                    onClick={() => setShowManualForm((prev) => !prev)}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    {showManualForm ? 'Ukryj formularz ręczny' : 'Dodaj wynik ręcznie'}
                  </Button>
                  <input
                    ref={resultsFileRef}
                    type="file"
                    accept=".json,.csv"
                    onChange={handleImportScanResults}
                    className="hidden"
                  />
                  <Button variant="secondary" onClick={() => resultsFileRef.current?.click()}>
                    <Upload className="h-3.5 w-3.5" />
                    Import wyników (JSON / CSV)
                  </Button>
                </>
              )}
              <Button
                variant="outline"
                disabled={exportingFmt !== null}
                onClick={async () => {
                  setExportingFmt('json');
                  setError(null);
                  try {
                    await downloadExport('json', role);
                  } catch (err) {
                    setError(err instanceof Error ? err.message : 'Błąd eksportu JSON');
                  } finally {
                    setExportingFmt(null);
                  }
                }}
              >
                <Download className="h-3.5 w-3.5" />
                {exportingFmt === 'json' ? 'Eksportowanie...' : 'Pobierz JSON'}
              </Button>
              <Button
                variant="outline"
                disabled={exportingFmt !== null}
                onClick={async () => {
                  setExportingFmt('csv');
                  setError(null);
                  try {
                    await downloadExport('csv', role);
                  } catch (err) {
                    setError(err instanceof Error ? err.message : 'Błąd eksportu CSV');
                  } finally {
                    setExportingFmt(null);
                  }
                }}
              >
                <Download className="h-3.5 w-3.5" />
                {exportingFmt === 'csv' ? 'Eksportowanie...' : 'Pobierz CSV'}
              </Button>
            </div>
          </div>

          {canAdd && showManualForm && (
            <form
              onSubmit={handleSubmitManualFinding}
              className="border-t border-border pt-4 space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">Adres IP *</span>
                  <Input
                    required
                    value={manIp}
                    onChange={(e) => setManIp(e.target.value)}
                    placeholder="np. 172.28.0.50"
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Hostname</span>
                  <Input
                    value={manHostname}
                    onChange={(e) => setManHostname(e.target.value)}
                    placeholder="np. dev-app.agh.edu.pl"
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Port *</span>
                  <Input
                    required
                    type="number"
                    min={1}
                    max={65535}
                    value={manPort}
                    onChange={(e) => setManPort(e.target.value)}
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Protokół</span>
                  <Select value={manProto} onChange={(e) => setManProto(e.target.value as 'tcp' | 'udp')}>
                    <option value="tcp">tcp</option>
                    <option value="udp">udp</option>
                  </Select>
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">Usługa (np. http, ssh)</span>
                  <Input value={manService} onChange={(e) => setManService(e.target.value)} className="font-mono" />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Produkt (np. nginx, WordPress)</span>
                  <Input value={manProduct} onChange={(e) => setManProduct(e.target.value)} />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Wersja</span>
                  <Input value={manVersion} onChange={(e) => setManVersion(e.target.value)} className="font-mono" />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Banner (opcjonalnie)</span>
                  <Input value={manBanner} onChange={(e) => setManBanner(e.target.value)} className="font-mono" />
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">URL HTTP/HTTPS</span>
                  <Input
                    value={manUrl}
                    onChange={(e) => setManUrl(e.target.value)}
                    placeholder="http://172.28.0.50:80/"
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Kod HTTP</span>
                  <Input
                    type="number"
                    min={100}
                    max={599}
                    value={manHttpStatus}
                    onChange={(e) => setManHttpStatus(e.target.value)}
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Tytuł strony</span>
                  <Input value={manTitle} onChange={(e) => setManTitle(e.target.value)} />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Technologie (po przecinku)</span>
                  <Input
                    value={manTechs}
                    onChange={(e) => setManTechs(e.target.value)}
                    placeholder="WordPress, PHP, nginx"
                  />
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">Nagłówki HTTP (Klucz: Wartość, po linii — wyzwalają sygnatury!)</span>
                  <textarea
                    rows={2}
                    value={manHeaders}
                    onChange={(e) => setManHeaders(e.target.value)}
                    placeholder={"X-Powered-By: PHP/8.1\nServer: nginx/1.27.0"}
                    className="w-full rounded-md border border-input bg-background px-2.5 py-1.5 text-xs font-mono text-foreground"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Ciasteczka (po przecinku)</span>
                  <Input
                    value={manCookies}
                    onChange={(e) => setManCookies(e.target.value)}
                    placeholder="PHPSESSID, JSESSIONID"
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Favicon MMH3 hash</span>
                  <Input
                    value={manFavicon}
                    onChange={(e) => setManFavicon(e.target.value)}
                    placeholder="-1986957532"
                    className="font-mono"
                  />
                </label>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
                <div className="flex items-center gap-5 text-foreground">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <Checkbox checked={manIsAdmin} onCheckedChange={(v) => setManIsAdmin(Boolean(v))} />
                    <span>Panel administracyjny</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <Checkbox checked={manIsStaging} onCheckedChange={(v) => setManIsStaging(Boolean(v))} />
                    <span>Środowisko Staging / Test</span>
                  </label>
                </div>
                <Button type="submit" disabled={submittingManual}>
                  <Plus className="h-3.5 w-3.5" />
                  {submittingManual ? 'Przetwarzanie...' : 'Zapisz przez ingest pipeline'}
                </Button>
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
