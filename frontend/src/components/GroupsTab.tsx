import {
  AlertCircle,
  BookmarkPlus,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Edit3,
  Filter,
  Layers,
  Play,
  RefreshCw,
  Search,
  Send,
  Trash2,
} from 'lucide-react';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type {
  AutoGroupCategory,
  AutoGroupItem,
  AutoGroupsResponse,
  GroupFilterRules,
  GroupMemberHost,
  GroupScanResponse,
  SavedGroupItem,
  UserRole,
} from '../types';
import { HostStatusBadge } from './Badges';
import { GroupBuilderPanel } from './groups/GroupBuilderPanel';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Checkbox } from './ui/checkbox';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
  initialSearch?: string | null;
  onInitialSearchConsumed?: () => void;
  onRefreshAll: () => void;
  onExportGroupToDefectDojo?: (hostIds: string[], groupLabel: string) => void;
}

interface ScanProfileOption {
  id: string;
  name: string;
  ports: string;
}

const CATEGORY_TABS: Array<{ key: 'all' | AutoGroupCategory; label: string }> = [
  { key: 'all', label: 'Wszystkie' },
  { key: 'technology', label: 'Technologie / CMS' },
  { key: 'port', label: 'Porty' },
  { key: 'classification', label: 'Klasyfikacja' },
  { key: 'signature', label: 'Sygnatury' },
  { key: 'override', label: 'Jednostki / Tagi' },
];

const CATEGORY_LABELS: Record<AutoGroupCategory, string> = {
  technology: 'tech',
  port: 'port',
  classification: 'klasyfikacja',
  signature: 'sygnatura',
  override: 'override',
};

function summarizeRules(rules: Partial<GroupFilterRules>): string[] {
  const chips: string[] = [];
  if (rules.technologies?.length) chips.push(`tech: ${rules.technologies.join(', ')}`);
  if (rules.ports?.length) chips.push(`port: ${rules.ports.join(', ')}`);
  if (rules.service_names?.length) chips.push(`svc: ${rules.service_names.join(', ')}`);
  if (rules.products?.length) chips.push(`prod: ${rules.products.join(', ')}`);
  if (rules.is_admin_panel === true) chips.push('admin_panel');
  if (rules.is_admin_panel === false) chips.push('!admin_panel');
  if (rules.is_staging_env === true) chips.push('staging');
  if (rules.is_staging_env === false) chips.push('!staging');
  if (rules.signature_ids?.length) chips.push(`sygnatury: ${rules.signature_ids.length}`);
  if (rules.owner_units?.length) chips.push(`jednostka: ${rules.owner_units.join(', ')}`);
  if (rules.tags?.length) chips.push(`tagi: ${rules.tags.map((t) => `#${t}`).join(', ')}`);
  if (rules.cidr_scope) chips.push(`cidr: ${rules.cidr_scope}`);
  if (rules.statuses?.length && !(rules.statuses.length === 2 && rules.statuses.includes('online') && rules.statuses.includes('unstable'))) {
    chips.push(`status: ${rules.statuses.join(',')}`);
  }
  if (chips.length > 1) {
    chips.unshift(rules.match_mode === 'any' ? 'LUB (OR)' : 'ORAZ (AND)');
  }
  return chips;
}

export function GroupsTab({
  role,
  initialSearch = null,
  onInitialSearchConsumed,
  onRefreshAll,
  onExportGroupToDefectDojo,
}: Props) {
  const [autoData, setAutoData] = useState<AutoGroupsResponse | null>(null);
  const [savedGroups, setSavedGroups] = useState<SavedGroupItem[]>([]);
  const [profiles, setProfiles] = useState<ScanProfileOption[]>([]);
  const [loading, setLoading] = useState(false);

  const [builderOpen, setBuilderOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<SavedGroupItem | null>(null);

  // Filtry auto-grup
  const [categoryFilter, setCategoryFilter] = useState<'all' | AutoGroupCategory>('all');
  const [search, setSearch] = useState('');

  // Parametry skanowania grupy (domyślnie pełny profil zgodnie z wyborem użytkownika)
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [portsMode, setPortsMode] = useState<'profile' | 'matched_ports' | 'custom'>('profile');
  const [customPorts, setCustomPorts] = useState('80,443,8080');
  const [windowMinutes, setWindowMinutes] = useState(30);
  const [dryRun, setDryRun] = useState(false);

  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [lastScanResult, setLastScanResult] = useState<GroupScanResponse | null>(null);
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [expandedMembers, setExpandedMembers] = useState<Record<string, GroupMemberHost[]>>({});
  const [loadingMembersKey, setLoadingMembersKey] = useState<string | null>(null);

  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canAdd = hasPermission(role, 'add');
  const canModify = hasPermission(role, 'modify');
  const canDelete = hasPermission(role, 'delete');

  async function loadAll() {
    setLoading(true);
    try {
      const [autoRes, savedRes, profRes] = await Promise.all([
        apiFetch<AutoGroupsResponse>('/groups/auto', role),
        apiFetch<SavedGroupItem[]>('/groups', role),
        apiFetch<ScanProfileOption[]>('/scans/profiles', role),
      ]);
      setAutoData(autoRes);
      setSavedGroups(savedRes);
      setProfiles(profRes);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania grup automatycznych');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
  }, [role]);

  useEffect(() => {
    if (!initialSearch) return;
    setSearch(initialSearch);
    setCategoryFilter('all');
    onInitialSearchConsumed?.();
  }, [initialSearch, onInitialSearchConsumed]);

  const filteredAutoGroups = useMemo(() => {
    const list = autoData?.groups || [];
    const q = search.trim().toLowerCase();
    return list.filter((g) => {
      if (categoryFilter !== 'all' && g.category !== categoryFilter) return false;
      if (!q) return true;
      return (
        g.label.toLowerCase().includes(q) ||
        g.description.toLowerCase().includes(q) ||
        g.sample_ips.some((ip) => ip.includes(q)) ||
        g.matched_ports.some((p) => String(p).includes(q))
      );
    });
  }, [autoData, categoryFilter, search]);

  async function runGroupScan(opts: {
    key: string;
    groupId?: string;
    filterRules?: GroupFilterRules;
    label: string;
  }) {
    if (!canAdd) return;
    setBusyKey(opts.key);
    setError(null);
    setNotice(null);
    setLastScanResult(null);
    try {
      const body: Record<string, unknown> = {
        group_label: opts.label,
        ports_mode: portsMode,
        window_minutes: windowMinutes,
        dry_run: dryRun,
      };
      if (opts.groupId) body.group_id = opts.groupId;
      if (opts.filterRules) body.filter_rules = opts.filterRules;
      if (selectedProfileId) body.profile_id = selectedProfileId;
      if (portsMode === 'custom') body.custom_ports = customPorts.trim();

      const res = await apiFetch<GroupScanResponse>('/groups/scan', role, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      setLastScanResult(res);
      if (res.dry_run) {
        setNotice(
          `Dry-Run dla grupy "${res.group_label}": ${res.matched_hosts_count} hostów, ${res.total_chunks} paczek, porty: ${res.ports}.`
        );
      } else {
        setNotice(
          `Uruchomiono skan grupy "${res.group_label}" (${res.scan_run_id?.slice(0, 8)}...): ${res.matched_hosts_count} hostów, porty: ${res.ports}, paczek: ${res.total_chunks}.`
        );
        onRefreshAll();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd uruchamiania skanu grupy');
    } finally {
      setBusyKey(null);
    }
  }

  async function handleSaveAutoGroup(g: AutoGroupItem) {
    if (!canAdd) return;
    setBusyKey(`save:${g.key}`);
    setError(null);
    setNotice(null);
    try {
      await apiFetch('/groups', role, {
        method: 'POST',
        body: JSON.stringify({
          name: `Auto: ${g.label}`,
          description: g.description,
          environment: 'all',
          filter_rules: g.filter_rules,
        }),
      });
      setNotice(`Zapisano "${g.label}" jako Smart Group (dostępna w Harmonogramach i DefectDojo).`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Nie udało się zapisać grupy');
    } finally {
      setBusyKey(null);
    }
  }

  async function handleDeleteSavedGroup(g: SavedGroupItem) {
    if (!canDelete) return;
    setBusyKey(`del:${g.id}`);
    setError(null);
    setNotice(null);
    try {
      await apiFetch(`/groups/${g.id}`, role, { method: 'DELETE' });
      if (editingGroup?.id === g.id) {
        setEditingGroup(null);
        setBuilderOpen(false);
      }
      setNotice(`Usunięto grupę dynamiczną "${g.name}".`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd usuwania grupy');
    } finally {
      setBusyKey(null);
    }
  }

  async function handleToggleMembers(key: string, rules: Partial<GroupFilterRules>) {
    if (expandedKey === key) {
      setExpandedKey(null);
      return;
    }
    setExpandedKey(key);
    if (expandedMembers[key]) return;
    setLoadingMembersKey(key);
    try {
      const res = await apiFetch<{ hosts: GroupMemberHost[] }>('/groups/preview', role, {
        method: 'POST',
        body: JSON.stringify(rules),
      });
      setExpandedMembers((prev) => ({ ...prev, [key]: res.hosts }));
    } catch {
      // ignore preview error
    } finally {
      setLoadingMembersKey(null);
    }
  }

  const canShowBuilder = Boolean(editingGroup ? canModify : canAdd);

  return (
    <div className="space-y-5">
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

      {/* Górny pasek: rozwijany kreator Smart Group + odświeżanie */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {canAdd && !editingGroup && (
            <Button
              type="button"
              size="sm"
              variant={builderOpen ? 'default' : 'outline'}
              onClick={() => setBuilderOpen((v) => !v)}
              className="h-8 px-3 text-xs"
            >
              <Filter className="h-3.5 w-3.5" />
              Kreator grupy dynamicznej
              {builderOpen ? (
                <ChevronUp className="h-3.5 w-3.5 ml-0.5" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5 ml-0.5" />
              )}
            </Button>
          )}
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={loading}
            onClick={() => {
              setExpandedMembers({});
              loadAll();
            }}
            className="h-8 px-2.5 text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Odśwież
          </Button>
        </div>
        <span className="text-[11px] font-mono text-muted-foreground">
          Auto-grupy na żywo: {autoData?.total_auto_groups ?? 0} • Zapisane Smart Groups: {savedGroups.length}
        </span>
      </div>

      {/* Rozwijany kreator własnej Smart Group */}
      {canShowBuilder && (builderOpen || editingGroup) && (
        <GroupBuilderPanel
          role={role}
          canAdd={canAdd}
          canModify={canModify}
          facets={autoData?.facets ?? null}
          editingGroup={editingGroup}
          onClose={() => setBuilderOpen(false)}
          onCancelEdit={() => {
            setEditingGroup(null);
            setBuilderOpen(false);
          }}
          onSaved={async (msg) => {
            setNotice(msg);
            setError(null);
            setEditingGroup(null);
            setBuilderOpen(false);
            setExpandedMembers({});
            await loadAll();
          }}
          onAdHocScan={(rules, label) =>
            runGroupScan({ key: 'adhoc', filterRules: rules, label })
          }
        />
      )}

      {/* Kompaktowy pasek parametrów skanu grupy (dla ról z add) */}
      {canAdd && (
        <Card>
          <CardContent className="p-3.5 flex flex-wrap items-end gap-3 text-xs">
            <label className="space-y-1 min-w-[180px] flex-1">
              <span className="text-[11px] text-muted-foreground">Profil skanowania grupy</span>
              <Select
                value={selectedProfileId}
                onChange={(e) => setSelectedProfileId(e.target.value)}
                className="h-8 font-mono text-xs"
              >
                <option value="">Domyślny (default-safe-lab)</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.ports.length > 26 ? `${p.ports.slice(0, 26)}…` : p.ports})
                  </option>
                ))}
              </Select>
            </label>

            <label className="space-y-1 min-w-[200px]">
              <span className="text-[11px] text-muted-foreground">Zakres portów skanu grupy</span>
              <Select
                value={portsMode}
                onChange={(e) => setPortsMode(e.target.value as 'profile' | 'matched_ports' | 'custom')}
                className="h-8 text-xs"
              >
                <option value="profile">Pełny profil (domyślnie)</option>
                <option value="matched_ports">Tylko porty wykryte w grupie (szybki)</option>
                <option value="custom">Własna lista portów</option>
              </Select>
            </label>

            {portsMode === 'custom' && (
              <label className="space-y-1 w-40">
                <span className="text-[11px] text-muted-foreground">Porty (nmap -p)</span>
                <Input
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  placeholder="80,443,8080"
                  className="h-8 font-mono text-xs"
                />
              </label>
            )}

            <label className="space-y-1 w-24">
              <span className="text-[11px] text-muted-foreground">Okno (min)</span>
              <Input
                type="number"
                min={1}
                max={1440}
                value={windowMinutes}
                onChange={(e) => setWindowMinutes(Number(e.target.value))}
                className="h-8 font-mono text-xs"
              />
            </label>

            <label className="flex items-center gap-2 cursor-pointer h-8 px-1 text-foreground">
              <Checkbox checked={dryRun} onCheckedChange={(v) => setDryRun(Boolean(v))} />
              <span>Dry-Run (podgląd)</span>
            </label>
          </CardContent>
        </Card>
      )}

      {/* Podgląd wyniku ostatniego skanu / Dry-Run */}
      {lastScanResult && (
        <Card>
          <CardHeader className="px-4 py-2.5 border-b border-border flex-row flex-wrap items-center justify-between gap-2 space-y-0">
            <CardTitle className="text-xs font-mono">
              {lastScanResult.dry_run ? 'Podgląd Dry-Run grupy:' : 'Uruchomiono skan grupy:'}{' '}
              {lastScanResult.group_label}
            </CardTitle>
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
              <Badge variant="default">Hosty: {lastScanResult.matched_hosts_count}</Badge>
              <Badge variant="secondary">Porty: {lastScanResult.ports}</Badge>
              <Badge variant="outline">Paczki: {lastScanResult.total_chunks}</Badge>
              {lastScanResult.scan_run_id && (
                <Badge variant="outline">Run: {lastScanResult.scan_run_id.slice(0, 8)}…</Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-3 text-[11px] font-mono text-muted-foreground flex flex-wrap gap-1.5">
            <span className="text-foreground">Wytypowane cele:</span>
            {lastScanResult.chunks.slice(0, 20).map((c) => (
              <Badge key={c} variant="outline" className="font-mono text-[10px]">
                {c}
              </Badge>
            ))}
            {lastScanResult.chunks.length > 20 && (
              <span>… (+{lastScanResult.chunks.length - 20} więcej)</span>
            )}
          </CardContent>
        </Card>
      )}

      {/* Sekcja 1: Auto-wykryte grupy (zero-config, liczone na żywo z bazy) */}
      <Card>
        <CardHeader className="px-4 py-3 border-b border-border space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-muted-foreground" />
                Automatyczne grupy wykryte w infrastrukturze ({filteredAutoGroups.length})
              </CardTitle>
              <CardDescription>
                Generowane na żywo wg wykrytych technologii/CMS, otwartych portów, flag ryzyka, sygnatur i jednostek — gotowe do celowanego skanu 1-klikiem.
              </CardDescription>
            </div>
            <div className="relative w-full sm:w-64">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Szukaj np. WordPress, 8080, admin..."
                className="pl-8 h-8 text-xs"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {CATEGORY_TABS.map((cat) => (
              <Button
                key={cat.key}
                type="button"
                size="sm"
                variant={categoryFilter === cat.key ? 'default' : 'outline'}
                onClick={() => setCategoryFilter(cat.key)}
                className="h-7 px-2.5 text-[11px]"
              >
                {cat.label}
              </Button>
            ))}
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Grupa automatyczna</TableHead>
                <TableHead>Kategoria</TableHead>
                <TableHead>Hosty</TableHead>
                <TableHead>Porty w grupie</TableHead>
                <TableHead>Przykładowe IP</TableHead>
                <TableHead className="text-right">Akcje</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAutoGroups.map((g) => {
                const isExpanded = expandedKey === g.key;
                const members = expandedMembers[g.key];
                return (
                  <Fragment key={g.key}>
                    <TableRow>
                      <TableCell>
                        <div className="font-medium text-foreground">{g.label}</div>
                        <div className="text-[11px] text-muted-foreground">{g.description}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="font-mono text-[10px]">
                          {CATEGORY_LABELS[g.category]}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          onClick={() => handleToggleMembers(g.key, g.filter_rules)}
                          className="h-7 px-2 font-mono text-xs"
                          title="Rozwiń listę hostów w tej grupie"
                        >
                          <Badge variant="default" className="font-mono">
                            {g.host_count}
                          </Badge>
                          {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                        </Button>
                      </TableCell>
                      <TableCell className="font-mono text-[11px]">
                        <div className="flex flex-wrap gap-1 max-w-[160px]">
                          {g.matched_ports.slice(0, 6).map((p) => (
                            <Badge key={p} variant="outline" className="font-mono text-[10px] px-1.5 py-0">
                              :{p}
                            </Badge>
                          ))}
                          {g.matched_ports.length > 6 && (
                            <span className="text-muted-foreground text-[10px]">
                              +{g.matched_ports.length - 6}
                            </span>
                          )}
                          {g.matched_ports.length === 0 && <span className="text-muted-foreground">—</span>}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground max-w-xs truncate">
                        {g.sample_ips.slice(0, 3).join(', ')}
                        {g.host_count > 3 ? ` (+${g.host_count - 3})` : ''}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap space-x-1">
                        {canAdd && (
                          <Button
                            type="button"
                            size="sm"
                            disabled={busyKey === g.key}
                            onClick={() =>
                              runGroupScan({
                                key: g.key,
                                filterRules: g.filter_rules,
                                label: g.label,
                              })
                            }
                            className="h-7 px-2.5 text-[11px]"
                          >
                            <Play className="h-3 w-3" />
                            {busyKey === g.key ? '...' : dryRun ? 'Dry-Run' : 'Skanuj'}
                          </Button>
                        )}
                        {canAdd && (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={busyKey === `save:${g.key}`}
                            onClick={() => handleSaveAutoGroup(g)}
                            className="h-7 px-2 text-[11px]"
                            title="Zapisz jako Smart Group (do harmonogramów i ponownego użycia)"
                          >
                            <BookmarkPlus className="h-3 w-3" />
                            Zapisz
                          </Button>
                        )}
                        {canModify && onExportGroupToDefectDojo && g.host_ids.length > 0 && (
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            onClick={() => onExportGroupToDefectDojo(g.host_ids, g.label)}
                            className="h-7 px-2 text-[11px]"
                            title="Zaznacz hosty tej grupy do eksportu w DefectDojo"
                          >
                            <Send className="h-3 w-3" />
                            DD
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="bg-muted/30 hover:bg-muted/30">
                        <TableCell colSpan={6} className="py-2.5 px-4">
                          {loadingMembersKey === g.key ? (
                            <div className="text-xs font-mono text-muted-foreground">Ładowanie hostów...</div>
                          ) : members && members.length > 0 ? (
                            <div className="flex flex-wrap gap-2">
                              {members.map((m) => (
                                <div
                                  key={m.id}
                                  className="inline-flex items-center gap-1.5 rounded border border-border bg-background px-2 py-1 text-[11px] font-mono"
                                >
                                  <span className="font-semibold text-foreground">{m.ip_address}</span>
                                  {m.hostname && <span className="text-muted-foreground">({m.hostname})</span>}
                                  <HostStatusBadge status={m.status} missedScans={m.missed_scans} />
                                  {m.open_ports.length > 0 && (
                                    <span className="text-muted-foreground">[{m.open_ports.join(',')}]</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-xs text-muted-foreground">Brak hostów.</div>
                          )}
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
              {filteredAutoGroups.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                    Brak automatycznych grup dla wybranego filtra. Uruchom skan, aby wykryć hosty i technologie.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Sekcja 2: Zapisane Grupy Dynamiczne (Smart Groups — dostępne też w Harmonogramach!) */}
      <Card>
        <CardHeader className="px-4 py-3 border-b border-border flex-row flex-wrap items-center justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-sm flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              Zapisane Grupy Dynamiczne — Smart Groups ({savedGroups.length})
            </CardTitle>
            <CardDescription>
              Własne kombinacje reguł (np. WordPress + port 8080) — lista IP odświeża się automatycznie przed każdym skanem i harmonogramem cron.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nazwa grupy</TableHead>
                <TableHead>Reguły doboru</TableHead>
                <TableHead>Dopasowane hosty</TableHead>
                <TableHead>Porty</TableHead>
                <TableHead className="text-right">Akcje</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {savedGroups.map((sg) => {
                const rowKey = `saved:${sg.id}`;
                const isExpanded = expandedKey === rowKey;
                const members = expandedMembers[rowKey];
                const ruleChips = summarizeRules(sg.filter_rules || {});
                return (
                  <Fragment key={sg.id}>
                    <TableRow>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium text-foreground">{sg.name}</span>
                          <Badge variant="outline" className="font-mono text-[9px] uppercase">
                            {sg.environment}
                          </Badge>
                        </div>
                        {sg.description && <div className="text-[11px] text-muted-foreground">{sg.description}</div>}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1 max-w-md">
                          {ruleChips.map((ch) => (
                            <Badge key={ch} variant="secondary" className="font-mono text-[10px]">
                              {ch}
                            </Badge>
                          ))}
                          {ruleChips.length === 0 && (
                            <span className="text-xs text-muted-foreground">Wszystkie aktywne hosty</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          onClick={() => handleToggleMembers(rowKey, sg.filter_rules || {})}
                          className="h-7 px-2 font-mono text-xs"
                        >
                          <Badge variant={sg.member_count > 0 ? 'default' : 'outline'} className="font-mono">
                            {sg.member_count}
                          </Badge>
                          {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                        </Button>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {sg.suggested_ports_spec || '—'}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap space-x-1">
                        {canAdd && (
                          <Button
                            type="button"
                            size="sm"
                            disabled={busyKey === rowKey || sg.member_count === 0}
                            onClick={() =>
                              runGroupScan({
                                key: rowKey,
                                groupId: sg.id,
                                label: sg.name,
                              })
                            }
                            className="h-7 px-2.5 text-[11px]"
                          >
                            <Play className="h-3 w-3" />
                            {busyKey === rowKey ? '...' : dryRun ? 'Dry-Run' : 'Skanuj'}
                          </Button>
                        )}
                        {canModify && onExportGroupToDefectDojo && sg.host_ids.length > 0 && (
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            onClick={() => onExportGroupToDefectDojo(sg.host_ids, sg.name)}
                            className="h-7 px-2 text-[11px]"
                            title="Zaznacz hosty tej grupy w DefectDojo"
                          >
                            <Send className="h-3 w-3" />
                            DD
                          </Button>
                        )}
                        {canModify && (
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              setEditingGroup(sg);
                              setBuilderOpen(true);
                              window.scrollTo({ top: 0, behavior: 'smooth' });
                            }}
                            className="h-7 px-2"
                          >
                            <Edit3 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            disabled={busyKey === `del:${sg.id}`}
                            onClick={() => handleDeleteSavedGroup(sg)}
                            className="h-7 px-2"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="bg-muted/30 hover:bg-muted/30">
                        <TableCell colSpan={5} className="py-2.5 px-4">
                          {loadingMembersKey === rowKey ? (
                            <div className="text-xs font-mono text-muted-foreground">Ładowanie hostów...</div>
                          ) : members && members.length > 0 ? (
                            <div className="flex flex-wrap gap-2">
                              {members.map((m) => (
                                <div
                                  key={m.id}
                                  className="inline-flex items-center gap-1.5 rounded border border-border bg-background px-2 py-1 text-[11px] font-mono"
                                >
                                  <span className="font-semibold text-foreground">{m.ip_address}</span>
                                  {m.hostname && <span className="text-muted-foreground">({m.hostname})</span>}
                                  <HostStatusBadge status={m.status} missedScans={m.missed_scans} />
                                  {m.open_ports.length > 0 && (
                                    <span className="text-muted-foreground">[{m.open_ports.join(',')}]</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-xs text-muted-foreground">
                              Brak hostów spełniających obecnie reguły tej grupy.
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
              {savedGroups.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-6 text-center text-muted-foreground">
                    Brak zapisanych Smart Groups. Kliknij <strong>Zapisz</strong> przy dowolnej auto-grupie powyżej albo otwórz{' '}
                    <strong>Kreator grupy dynamicznej</strong>.
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
