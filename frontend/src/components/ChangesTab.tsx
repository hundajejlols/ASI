import { AlertCircle, Check, GitCompare } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type { ChangeEvent, ScanCompareResult, ScanRunInfo, UserRole } from '../types';
import { ChangeTypeBadge, formatTime, SeverityBadge } from './Badges';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Select } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
  changes: ChangeEvent[];
  onRefresh: () => void;
}

const CHANGE_TYPES = [
  'all',
  'host_new',
  'host_offline',
  'host_recovered',
  'service_new',
  'service_closed',
  'service_changed',
  'signature_matched',
  'tls_changed',
  'tech_changed',
];

export function ChangesTab({ role, changes, onRefresh }: Props) {
  const [typeFilter, setTypeFilter] = useState('all');
  const [runFilter, setRunFilter] = useState('all');
  const [scanRuns, setScanRuns] = useState<ScanRunInfo[]>([]);
  const [runA, setRunA] = useState('');
  const [runB, setRunB] = useState('');
  const [comparing, setComparing] = useState(false);
  const [compareResult, setCompareResult] = useState<ScanCompareResult | null>(null);
  const [compareError, setCompareError] = useState<string | null>(null);
  const [ackBusyId, setAckBusyId] = useState<string | null>(null);

  const canModify = hasPermission(role, 'modify');

  useEffect(() => {
    apiFetch<ScanRunInfo[]>('/scans/runs?limit=25', role)
      .then((runs) => {
        setScanRuns(runs);
        if (runs.length >= 2 && !runA && !runB) {
          setRunA(runs[1].id);
          setRunB(runs[0].id);
        }
      })
      .catch(() => {});
  }, [role, changes]);

  async function handleCompare() {
    if (!runA || !runB) return;
    setComparing(true);
    setCompareError(null);
    try {
      const res = await apiFetch<ScanCompareResult>(
        `/scans/compare?run_a=${encodeURIComponent(runA)}&run_b=${encodeURIComponent(runB)}`,
        role
      );
      setCompareResult(res);
    } catch (e) {
      setCompareError(e instanceof Error ? e.message : 'Błąd porównania przebiegów');
    } finally {
      setComparing(false);
    }
  }

  async function handleAcknowledge(ev: ChangeEvent) {
    if (!canModify) return;
    setAckBusyId(ev.id);
    try {
      await apiFetch(`/changes/${ev.id}/acknowledge`, role, {
        method: 'PATCH',
        body: JSON.stringify({ acknowledged: !ev.acknowledged }),
      });
      onRefresh();
    } catch {
      // ignore
    } finally {
      setAckBusyId(null);
    }
  }

  const uniqueRuns = useMemo(() => {
    const seen = new Map<string, string>();
    for (const c of changes) {
      if (c.scan_run_id && !seen.has(c.scan_run_id)) {
        seen.set(c.scan_run_id, c.detected_at);
      }
    }
    return Array.from(seen.entries());
  }, [changes]);

  const filtered = changes.filter(
    (c) =>
      (typeFilter === 'all' || c.change_type === typeFilter) &&
      (runFilter === 'all' || c.scan_run_id === runFilter)
  );

  return (
    <div className="space-y-4">
      {/* Porównanie dwóch dowolnych przebiegów skanu (Skan A vs Skan B) */}
      <Card>
        <CardHeader className="px-4 py-3 border-b border-border">
          <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <GitCompare className="h-3.5 w-3.5" />
            Porównanie dwóch przebiegów skanu (Skan A vs Skan B)
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4 space-y-3 text-xs">
          <div className="flex flex-wrap items-end gap-3">
            <label className="space-y-1 flex-1 min-w-[220px]">
              <span className="text-muted-foreground">Skan bazowy (A)</span>
              <Select value={runA} onChange={(e) => setRunA(e.target.value)} className="h-8 font-mono text-xs">
                <option value="">Wybierz skan A...</option>
                {scanRuns.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.id.slice(0, 8)} • {r.status} • {formatTime(r.started_at || r.created_at)}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-1 flex-1 min-w-[220px]">
              <span className="text-muted-foreground">Skan porównywany (B)</span>
              <Select value={runB} onChange={(e) => setRunB(e.target.value)} className="h-8 font-mono text-xs">
                <option value="">Wybierz skan B...</option>
                {scanRuns.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.id.slice(0, 8)} • {r.status} • {formatTime(r.started_at || r.created_at)}
                  </option>
                ))}
              </Select>
            </label>
            <Button size="sm" onClick={handleCompare} disabled={!runA || !runB || comparing}>
              <GitCompare className="h-3.5 w-3.5" />
              {comparing ? 'Porównywanie...' : 'Porównaj skany'}
            </Button>
          </div>

          {compareError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <AlertDescription className="text-foreground">{compareError}</AlertDescription>
            </Alert>
          )}

          {compareResult && (
            <div className="space-y-2.5 pt-2 border-t border-border">
              <div className="flex flex-wrap gap-2 font-mono text-[11px]">
                <Badge variant="secondary">Endpointy A: {compareResult.summary.run_a_endpoints}</Badge>
                <Badge variant="secondary">Endpointy B: {compareResult.summary.run_b_endpoints}</Badge>
                <Badge variant="default">Nowe (+): {compareResult.summary.added}</Badge>
                <Badge variant="outline">Zniknęły (-): {compareResult.summary.removed}</Badge>
                <Badge variant="secondary">Zmienione (~): {compareResult.summary.changed}</Badge>
                <Badge variant="outline">Zdarzenia Diff pomiędzy: {compareResult.summary.change_events_between}</Badge>
              </div>
              {compareResult.added_endpoints.length > 0 && (
                <div className="font-mono text-[11px] text-emerald-400">
                  + Nowe w B: {compareResult.added_endpoints.map((e) => `${e.host_ip}:${e.port}`).join(', ')}
                </div>
              )}
              {compareResult.removed_endpoints.length > 0 && (
                <div className="font-mono text-[11px] text-rose-400">
                  - Brak w B (były w A): {compareResult.removed_endpoints.map((e) => `${e.host_ip}:${e.port}`).join(', ')}
                </div>
              )}
              {compareResult.changed_endpoints.length > 0 && (
                <pre className="p-2.5 rounded-md bg-muted border border-border text-[11px] font-mono overflow-x-auto">
                  {JSON.stringify(compareResult.changed_endpoints, null, 2)}
                </pre>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs font-mono text-muted-foreground">{filtered.length} zdarzeń</span>
          <div className="w-64">
            <Select
              value={runFilter}
              onChange={(e) => setRunFilter(e.target.value)}
              className="h-8 font-mono text-xs"
              aria-label="Filtr przebiegu skanu"
            >
              <option value="all">Wszystkie przebiegi skanów</option>
              {uniqueRuns.map(([runId, detectedAt]) => (
                <option key={runId} value={runId}>
                  Skan {runId.slice(0, 8)}... ({formatTime(detectedAt)})
                </option>
              ))}
            </Select>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {CHANGE_TYPES.map((ct) => (
            <Button
              key={ct}
              size="sm"
              variant={typeFilter === ct ? 'default' : 'outline'}
              onClick={() => setTypeFilter(ct)}
              className="font-mono"
            >
              {ct}
            </Button>
          ))}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Wykryto</TableHead>
                <TableHead>Typ</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Host / Usługa</TableHead>
                <TableHead>Poprzedni stan</TableHead>
                <TableHead>Nowy stan</TableHead>
                <TableHead className="text-right">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((ev) => (
                <TableRow key={ev.id} className="align-top">
                  <TableCell className="text-muted-foreground font-mono whitespace-nowrap">
                    {formatTime(ev.detected_at)}
                  </TableCell>
                  <TableCell>
                    <ChangeTypeBadge type={ev.change_type} />
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={ev.severity} />
                  </TableCell>
                  <TableCell className="font-mono whitespace-nowrap">
                    {ev.host_ip || ev.host_id.slice(0, 8)}
                    {ev.service_port ? `:${ev.service_port}/${ev.service_protocol}` : ''}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-muted-foreground max-w-xs break-all">
                    {ev.previous_value ? JSON.stringify(ev.previous_value) : '—'}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-foreground max-w-xs break-all">
                    {ev.current_value ? JSON.stringify(ev.current_value) : '—'}
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    {canModify ? (
                      <Button
                        size="sm"
                        variant={ev.acknowledged ? 'secondary' : 'outline'}
                        disabled={ackBusyId === ev.id}
                        onClick={() => handleAcknowledge(ev)}
                        className="h-7 px-2 text-[11px]"
                      >
                        <Check className="h-3 w-3" />
                        {ev.acknowledged ? 'Potwierdzone' : 'Potwierdź'}
                      </Button>
                    ) : (
                      <Badge variant={ev.acknowledged ? 'secondary' : 'outline'} className="font-mono text-[10px]">
                        {ev.acknowledged ? 'ACK' : 'NOWE'}
                      </Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    Brak zmian dla wybranego filtra.
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
