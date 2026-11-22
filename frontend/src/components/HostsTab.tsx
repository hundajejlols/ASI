import {
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Search,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { apiFetchPaginated } from '../api';
import type { HostSummary, SignatureDraft, UserRole } from '../types';
import { formatTime, HostStatusBadge } from './Badges';
import { HostDetailSheet } from './HostDetailSheet';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent } from './ui/card';
import { Input } from './ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
  hosts: HostSummary[];
  onRefresh: () => void;
  onCreateSignature?: (draft: SignatureDraft) => void;
}

const PAGE_SIZE = 50;

export function HostsTab({ role, hosts: initialHosts, onRefresh, onCreateSignature }: Props) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [page, setPage] = useState(0);
  const [pagedHosts, setPagedHosts] = useState<HostSummary[]>(initialHosts);
  const [totalHostsCount, setTotalHostsCount] = useState(initialHosts.length);
  const [loadingList, setLoadingList] = useState(false);

  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Serwerowe filtrowanie i paginacja (skalowalne >10 000 hostów)
  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(async () => {
      setLoadingList(true);
      try {
        const params = new URLSearchParams();
        params.set('limit', String(PAGE_SIZE));
        params.set('offset', String(page * PAGE_SIZE));
        if (statusFilter !== 'all') params.set('status', statusFilter);
        if (search.trim()) params.set('search', search.trim());
        const res = await apiFetchPaginated<HostSummary[]>(`/hosts?${params.toString()}`, role);
        if (!cancelled) {
          setPagedHosts(res.data);
          setTotalHostsCount(res.totalCount);
        }
      } catch {
        if (!cancelled) {
          setPagedHosts(initialHosts);
          setTotalHostsCount(initialHosts.length);
        }
      } finally {
        if (!cancelled) setLoadingList(false);
      }
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [role, search, statusFilter, page, initialHosts]);

  const handleCloseDetail = useCallback(() => {
    setSelectedHostId(null);
  }, []);

  const totalPages = Math.max(1, Math.ceil(totalHostsCount / PAGE_SIZE));

  return (
    <div className="space-y-4">
      {loadError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <AlertDescription className="text-foreground">{loadError}</AlertDescription>
        </Alert>
      )}
      {/* Pasek filtrów (filtrowanie serwerowe) */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <div className="relative w-full sm:w-80">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              placeholder="Szukaj w bazie po IP, hostname, etykiecie, jednostce, tagu..."
              className="pl-8"
            />
          </div>
          <span className="text-xs font-mono text-muted-foreground shrink-0">
            {loadingList ? '...' : `${totalHostsCount} hostów`}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {['all', 'online', 'unstable', 'offline'].map((st) => (
            <Button
              key={st}
              size="sm"
              variant={statusFilter === st ? 'default' : 'outline'}
              onClick={() => {
                setStatusFilter(st);
                setPage(0);
              }}
              className="font-mono"
            >
              {st === 'all' ? 'Wszystkie' : st}
            </Button>
          ))}
        </div>
      </div>

      {/* Tabela hostów */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IP</TableHead>
                <TableHead>Hostname / Etykieta</TableHead>
                <TableHead>Status (missed)</TableHead>
                <TableHead>Usługi</TableHead>
                <TableHead>Technologie / Tagi</TableHead>
                <TableHead>Flagi</TableHead>
                <TableHead>Ostatnio widziany</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pagedHosts.map((h) => (
                <TableRow
                  key={h.id}
                  onClick={() => {
                    setLoadError(null);
                    setSelectedHostId(h.id);
                  }}
                  className="cursor-pointer"
                >
                  <TableCell className="font-mono font-semibold text-foreground">{h.ip_address}</TableCell>
                  <TableCell>
                    <div className="font-medium text-foreground">
                      {h.override?.custom_label || h.hostname || '—'}
                    </div>
                    {h.override?.custom_label && h.hostname && (
                      <div className="text-[11px] text-muted-foreground font-mono">{h.hostname}</div>
                    )}
                    {h.override?.owner_unit && (
                      <div className="text-[11px] text-muted-foreground">{h.override.owner_unit}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <HostStatusBadge status={h.status} missedScans={h.missed_scans} />
                  </TableCell>
                  <TableCell className="font-mono">
                    {h.open_services_count}
                    {(h.signature_matches_count ?? 0) > 0 && (
                      <span className="ml-1.5 text-[11px] text-muted-foreground">
                        ({h.signature_matches_count} sig)
                      </span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(h.technologies || []).map((tech) => (
                        <Badge key={`tech-${tech}`} variant="outline" className="font-mono text-[10px]">
                          {tech}
                        </Badge>
                      ))}
                      {(h.override?.tags || []).map((t) => (
                        <Badge key={t} variant="secondary" className="font-mono">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="space-x-1">
                    {h.is_admin_panel && (
                      <Badge variant="default" className="uppercase font-mono text-[10px]">
                        ADMIN PANEL
                      </Badge>
                    )}
                    {h.is_staging_env && (
                      <Badge variant="outline" className="uppercase font-mono text-[10px]">
                        STAGING
                      </Badge>
                    )}
                    {h.override?.is_ignored && (
                      <Badge variant="outline" className="uppercase font-mono text-[10px]">
                        ignored
                      </Badge>
                    )}
                    {h.override?.is_false_positive && (
                      <Badge variant="secondary" className="uppercase font-mono text-[10px]">
                        false positive
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground font-mono whitespace-nowrap">
                    {formatTime(h.last_seen_at)}
                  </TableCell>
                </TableRow>
              ))}
              {pagedHosts.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    Brak hostów pasujących do filtra.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Paginacja serwerowa */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
          <span>
            Strona {page + 1} z {totalPages} (łącznie {totalHostsCount})
          </span>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
              <ChevronLeft className="h-3.5 w-3.5" />
              Poprzednia
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Następna
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}

      {/* Wspólny panel boczny szczegółów hosta i formularza asset_overrides */}
      <HostDetailSheet
        hostId={selectedHostId}
        onClose={handleCloseDetail}
        role={role}
        onRefresh={onRefresh}
        onCreateSignature={onCreateSignature}
        onError={setLoadError}
      />
    </div>
  );
}
