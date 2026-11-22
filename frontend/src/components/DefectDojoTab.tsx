import { AlertCircle, CheckCircle2, Plug, Search, Send, Server, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type {
  AutoGroupItem,
  AutoGroupsResponse,
  DefectDojoConfig,
  DefectDojoExportResponse,
  HostSummary,
  SavedGroupItem,
  UserRole,
} from '../types';
import { formatTime } from './Badges';
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
  hosts?: HostSummary[];
  preselectedHostIds?: string[] | null;
  preselectedGroupLabel?: string | null;
  onPreselectionConsumed?: () => void;
}

export function DefectDojoTab({
  role,
  hosts = [],
  preselectedHostIds = null,
  preselectedGroupLabel = null,
  onPreselectionConsumed,
}: Props) {
  const [config, setConfig] = useState<DefectDojoConfig | null>(null);
  const [baseUrl, setBaseUrl] = useState('');
  const [productTypeName, setProductTypeName] = useState('AGH Attack Surface');
  const [engagementName, setEngagementName] = useState('Janus ASI — Attack Surface');
  const [verifyTls, setVerifyTls] = useState(true);
  const [apiToken, setApiToken] = useState('');

  const [onlyInteresting, setOnlyInteresting] = useState(false);
  const [closeOldFindings, setCloseOldFindings] = useState(true);
  const [dryRun, setDryRun] = useState(true);
  const [selectedHostIds, setSelectedHostIds] = useState<string[]>([]);
  const [savedGroups, setSavedGroups] = useState<SavedGroupItem[]>([]);
  const [autoGroups, setAutoGroups] = useState<AutoGroupItem[]>([]);
  const [selectedGroupPreset, setSelectedGroupPreset] = useState('');
  const [hostSearch, setHostSearch] = useState('');
  const [visibleHosts, setVisibleHosts] = useState<HostSummary[]>(hosts);
  const [searchingHosts, setSearchingHosts] = useState(false);

  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null);
  const [exportResult, setExportResult] = useState<DefectDojoExportResponse | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savingConfig, setSavingConfig] = useState(false);
  const [testingConn, setTestingConn] = useState(false);
  const [busy, setBusy] = useState(false);

  const isAdmin = hasPermission(role, 'manage_integrations');
  const canExport = hasPermission(role, 'modify');

  async function loadConfig() {
    try {
      const data = await apiFetch<DefectDojoConfig>('/integrations/defectdojo', role);
      setConfig(data);
      if (data.base_url) setBaseUrl(data.base_url);
      if (data.product_type_name) setProductTypeName(data.product_type_name);
      if (data.engagement_name) setEngagementName(data.engagement_name);
      setVerifyTls(data.verify_tls);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania konfiguracji DefectDojo');
    }
  }

  useEffect(() => {
    setError(null);
    setNotice(null);
    setTestResult(null);
    setExportResult(null);
    loadConfig();
    Promise.all([
      apiFetch<SavedGroupItem[]>('/groups', role).catch(() => []),
      apiFetch<AutoGroupsResponse>('/groups/auto', role).catch(() => null),
    ]).then(([sg, ag]) => {
      setSavedGroups(sg || []);
      setAutoGroups(ag?.groups || []);
    });
  }, [role]);

  useEffect(() => {
    if (!preselectedHostIds || preselectedHostIds.length === 0) return;
    setSelectedHostIds(preselectedHostIds);
    setNotice(
      `Zaznaczono ${preselectedHostIds.length} hostów z grupy "${preselectedGroupLabel || 'Smart Group'}" do eksportu (1 IP = 1 Asset).`
    );
    onPreselectionConsumed?.();
  }, [preselectedHostIds, preselectedGroupLabel, onPreselectionConsumed]);

  // Synchronizuj listę hostów (z serwerowym wyszukiwaniem dla dużych sieci >10 000 IP)
  useEffect(() => {
    const q = hostSearch.trim();
    if (!q) {
      setVisibleHosts(hosts);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(async () => {
      setSearchingHosts(true);
      try {
        const found = await apiFetch<HostSummary[]>(
          `/hosts?search=${encodeURIComponent(q)}&limit=100`,
          role
        );
        if (!cancelled) setVisibleHosts(found);
      } catch {
        if (!cancelled) {
          const ql = q.toLowerCase();
          setVisibleHosts(
            hosts.filter(
              (h) =>
                h.ip_address.toLowerCase().includes(ql) ||
                (h.hostname || '').toLowerCase().includes(ql) ||
                (h.override?.custom_label || '').toLowerCase().includes(ql) ||
                (h.override?.owner_unit || '').toLowerCase().includes(ql)
            )
          );
        }
      } finally {
        if (!cancelled) setSearchingHosts(false);
      }
    }, 220);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [hostSearch, hosts, role]);

  async function handleSaveConfig(e: React.FormEvent) {
    e.preventDefault();
    if (!isAdmin) return;
    setError(null);
    setNotice(null);
    setSavingConfig(true);
    try {
      const payload: Record<string, unknown> = {
        base_url: baseUrl.trim(),
        product_type_name: productTypeName.trim() || 'AGH Attack Surface',
        engagement_name: engagementName.trim() || 'Janus ASI — Attack Surface',
        verify_tls: verifyTls,
        is_active: true,
      };
      if (apiToken.trim()) {
        payload.api_token = apiToken.trim();
      }
      const saved = await apiFetch<DefectDojoConfig>('/integrations/defectdojo', role, {
        method: 'PUT',
        body: JSON.stringify(payload),
      });
      setConfig(saved);
      setApiToken('');
      setNotice('Konfiguracja DefectDojo zapisana (token zaszyfrowany AES-256-GCM, model 1 IP = 1 Asset).');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu konfiguracji');
    } finally {
      setSavingConfig(false);
    }
  }

  async function handleTestConnection() {
    if (!isAdmin) return;
    setError(null);
    setNotice(null);
    setTestResult(null);
    setTestingConn(true);
    try {
      const res = await apiFetch<Record<string, unknown>>('/integrations/defectdojo/test', role, {
        method: 'POST',
      });
      setTestResult(res);
      if (res.ok) {
        setNotice(String(res.detail || 'Połączenie z DefectDojo API v2 działa poprawnie.'));
      } else {
        setError(String(res.detail || 'Test połączenia z DefectDojo nie powiódł się.'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd testu połączenia');
    } finally {
      setTestingConn(false);
    }
  }

  function toggleHostSelection(hostId: string, checked: boolean) {
    setSelectedHostIds((prev) =>
      checked ? (prev.includes(hostId) ? prev : [...prev, hostId]) : prev.filter((id) => id !== hostId)
    );
  }

  function selectAllVisible() {
    setSelectedHostIds((prev) => {
      const merged = new Set(prev);
      for (const h of visibleHosts) merged.add(h.id);
      return Array.from(merged);
    });
  }

  function handleSelectFromGroup(value: string) {
    setSelectedGroupPreset(value);
    if (!value) return;
    if (value.startsWith('saved:')) {
      const id = value.slice(6);
      const grp = savedGroups.find((g) => g.id === id);
      if (grp) {
        setSelectedHostIds(grp.host_ids);
        setNotice(`Zaznaczono ${grp.host_ids.length} hostów ze Smart Group "${grp.name}".`);
      }
    } else if (value.startsWith('auto:')) {
      const key = value.slice(5);
      const grp = autoGroups.find((g) => g.key === key);
      if (grp) {
        setSelectedHostIds(grp.host_ids);
        setNotice(`Zaznaczono ${grp.host_ids.length} hostów z auto-grupy "${grp.label}".`);
      }
    }
  }

  async function handleExport() {
    if (!canExport) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    setExportResult(null);
    try {
      const bodyPayload: Record<string, unknown> = {
        only_interesting: onlyInteresting,
        close_old_findings: closeOldFindings,
        dry_run: dryRun,
      };
      if (selectedHostIds.length > 0) {
        bodyPayload.host_ids = selectedHostIds;
      }
      const res = await apiFetch<DefectDojoExportResponse>('/integrations/defectdojo/export', role, {
        method: 'POST',
        body: JSON.stringify(bodyPayload),
      });
      setExportResult(res);
      if (dryRun) {
        setNotice(
          `Wygenerowano podgląd Dry-Run: ${res.stats.assets_to_export} osobnych Assetów (IP), ${res.stats.total_findings} znalezisk.`
        );
      } else if (res.partial_failure) {
        setNotice(
          `Częściowy eksport: wyeksportowano ${res.stats.assets_exported ?? 0} Assetów (błędy: ${res.stats.assets_failed ?? 0}). Sprawdź szczegóły poniżej.`
        );
      } else {
        setNotice(
          `Wyeksportowano ${res.stats.assets_exported ?? 0} Assetów (utworzono: ${res.stats.assets_created ?? 0}, zaktualizowano: ${res.stats.assets_updated ?? 0}, znalezisk: ${res.stats.total_findings}).`
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd eksportu do DefectDojo');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Konfiguracja DefectDojo */}
        <Card>
          <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle className="flex items-center gap-2">
                <span>Konfiguracja DefectDojo API v2</span>
              </CardTitle>
              <CardDescription>
                Token API: {config?.has_api_token ? 'Zapisany (AES-256-GCM, ukryty)' : 'Brak'}
                {config?.updated_at ? ` • ${formatTime(config.updated_at)}` : ''}
              </CardDescription>
            </div>
            <div className="flex items-center gap-1.5">
              <Badge variant="secondary" className="font-mono text-[10px]">
                1 IP = 1 Asset
              </Badge>
              <Badge variant={config?.configured ? 'default' : 'outline'} className="font-mono">
                {config?.configured ? 'Skonfigurowane' : 'Nieskonfigurowane'}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSaveConfig} className="space-y-3 text-xs">
              <div className="rounded-md bg-muted/40 border border-border p-2.5 text-[11px] text-muted-foreground space-y-1">
                <div className="font-medium text-foreground flex items-center gap-1.5">
                  <Server className="h-3.5 w-3.5" />
                  <span>Izolacja uprawnień per IP (Asset / Product)</span>
                </div>
                <p>
                  Każdy adres IP trafia do własnego Assetu (<code>product_name = IP</code>) przez{' '}
                  <code>/api/v2/reimport-scan/</code> z <code>auto_create_context=true</code>. Nowe Assety dziedziczą
                  Organizację (Product Type) z <code>asset_overrides.owner_unit</code> (jeśli ustawione) albo z pola
                  poniżej; istniejące Assety zachowują organizację ustawioną w DefectDojo.
                </p>
              </div>

              <label className="block space-y-1">
                <span className="text-muted-foreground">Base URL DefectDojo</span>
                <Input
                  disabled={!isAdmin}
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="http://host.docker.internal:8080"
                  className="font-mono"
                />
              </label>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">Domyślna Organizacja (Product Type)</span>
                  <Input
                    disabled={!isAdmin}
                    value={productTypeName}
                    onChange={(e) => setProductTypeName(e.target.value)}
                    placeholder="AGH Attack Surface"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Nazwa Engagement (per Asset)</span>
                  <Input
                    disabled={!isAdmin}
                    value={engagementName}
                    onChange={(e) => setEngagementName(e.target.value)}
                    placeholder="Janus ASI — Attack Surface"
                  />
                </label>
              </div>

              {isAdmin && (
                <label className="block space-y-1">
                  <span className="text-muted-foreground">
                    Nowy token API v2 (zostaw puste, aby zachować istniejący)
                  </span>
                  <Input
                    type="password"
                    value={apiToken}
                    onChange={(e) => setApiToken(e.target.value)}
                    placeholder="Token API v2 (wymaga uprawnień do tworzenia Assetów)"
                    className="font-mono"
                  />
                </label>
              )}

              <label className="flex items-center gap-2 pt-1 text-foreground cursor-pointer">
                <Checkbox
                  disabled={!isAdmin}
                  checked={verifyTls}
                  onCheckedChange={(v) => setVerifyTls(Boolean(v))}
                />
                <span>Weryfikuj certyfikat TLS</span>
              </label>

              {isAdmin ? (
                <div className="flex items-center gap-2 pt-2">
                  <Button type="submit" disabled={savingConfig || testingConn}>
                    <ShieldCheck className="h-3.5 w-3.5" />
                    {savingConfig ? 'Zapisywanie...' : 'Zapisz konfigurację'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={testingConn || savingConfig}
                    onClick={handleTestConnection}
                  >
                    <Plug className="h-3.5 w-3.5" />
                    {testingConn ? 'Testowanie...' : 'Test Connection'}
                  </Button>
                </div>
              ) : (
                <p className="text-muted-foreground pt-1">
                  Edycja konfiguracji DefectDojo dostępna wyłącznie dla roli <code className="font-mono">admin</code>.
                </p>
              )}

              {testResult && (
                <pre className="p-3 rounded-md bg-muted border border-border text-[11px] font-mono text-foreground overflow-x-auto">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              )}
            </form>
          </CardContent>
        </Card>

        {/* Panel eksportu do DefectDojo */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle>Eksport (Generic Findings Import — per IP)</CardTitle>
            <CardDescription>
              Każde zaznaczone IP zostanie zsynchronizowane z osobnym Assetem w DefectDojo.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <div className="space-y-2.5 text-foreground">
              <label className="flex items-center gap-2 cursor-pointer">
                <Checkbox
                  disabled={!canExport}
                  checked={onlyInteresting}
                  onCheckedChange={(v) => {
                    const checked = Boolean(v);
                    setOnlyInteresting(checked);
                    setCloseOldFindings(!checked);
                  }}
                />
                <span>Tylko istotne znaleziska (sygnatury, admin, staging, Diff, infra)</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <Checkbox
                  disabled={!canExport}
                  checked={closeOldFindings}
                  onCheckedChange={(v) => setCloseOldFindings(Boolean(v))}
                />
                <span>Zamknij stare/ignorowane znaleziska per IP przy reimporcie (close_old_findings)</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <Checkbox
                  disabled={!canExport}
                  checked={dryRun}
                  onCheckedChange={(v) => setDryRun(Boolean(v))}
                />
                <span>Dry-Run (podgląd per Asset bez wysyłki HTTP)</span>
              </label>
            </div>

            <div className="space-y-2 border-t border-border pt-3">
              <div className="flex flex-wrap items-center justify-between gap-2 text-muted-foreground">
                <span>
                  Wybierz hosty do eksportu ({selectedHostIds.length === 0 ? 'wszystkie' : `wybrano: ${selectedHostIds.length}`}):
                </span>
                {canExport && (
                  <div className="flex items-center gap-2">
                    {visibleHosts.length > 0 && (
                      <button
                        type="button"
                        onClick={selectAllVisible}
                        className="text-[11px] underline hover:text-foreground"
                      >
                        Zaznacz widoczne ({visibleHosts.length})
                      </button>
                    )}
                    {selectedHostIds.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedHostIds([])}
                        className="text-[11px] underline hover:text-foreground"
                      >
                        Wyczyść
                      </button>
                    )}
                  </div>
                )}
              </div>

              {canExport && (savedGroups.length > 0 || autoGroups.length > 0) && (
                <Select
                  value={selectedGroupPreset}
                  onChange={(e) => handleSelectFromGroup(e.target.value)}
                  className="h-8 text-xs font-mono"
                  aria-label="Zaznacz hosty z grupy automatycznej"
                >
                  <option value="">Szybki wybór z grupy (Smart Group / Auto-Grupa)...</option>
                  {savedGroups.length > 0 && (
                    <optgroup label="Zapisane Smart Groups">
                      {savedGroups.map((sg) => (
                        <option key={sg.id} value={`saved:${sg.id}`}>
                          [SMART] {sg.name} ({sg.member_count} hostów)
                        </option>
                      ))}
                    </optgroup>
                  )}
                  {autoGroups.length > 0 && (
                    <optgroup label="Auto-wykryte grupy (na żywo)">
                      {autoGroups.slice(0, 25).map((ag) => (
                        <option key={ag.key} value={`auto:${ag.key}`}>
                          [AUTO] {ag.label} ({ag.host_count} hostów)
                        </option>
                      ))}
                    </optgroup>
                  )}
                </Select>
              )}

              <div className="relative">
                <Search className="h-3.5 w-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
                <Input
                  value={hostSearch}
                  onChange={(e) => setHostSearch(e.target.value)}
                  placeholder="Szukaj IP, hostname, etykiety lub jednostki (np. 172.28.0.)..."
                  className="pl-8 h-8 text-xs font-mono"
                />
              </div>

              <div className="grid grid-cols-1 gap-1.5 max-h-40 overflow-y-auto p-2 rounded-md bg-muted/50 border border-border">
                {searchingHosts && (
                  <div className="text-center text-muted-foreground py-2 font-mono text-[11px]">
                    Wyszukiwanie hostów...
                  </div>
                )}
                {!searchingHosts &&
                  visibleHosts.map((h) => (
                    <label key={h.id} className="flex items-center justify-between gap-2 cursor-pointer">
                      <div className="flex items-center gap-2 min-w-0">
                        <Checkbox
                          disabled={!canExport}
                          checked={selectedHostIds.includes(h.id)}
                          onCheckedChange={(v) => toggleHostSelection(h.id, Boolean(v))}
                        />
                        <span className="font-mono text-foreground shrink-0">{h.ip_address}</span>
                        <span className="text-muted-foreground truncate">
                          {h.override?.custom_label || h.hostname || ''}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {h.override?.owner_unit && (
                          <Badge variant="secondary" className="font-mono text-[9px] px-1 py-0" title="Organizacja (Product Type) w DefectDojo">
                            {h.override.owner_unit}
                          </Badge>
                        )}
                        {(h.override?.is_ignored || h.override?.is_false_positive) && (
                          <Badge variant="outline" className="font-mono text-[9px] px-1 py-0">
                            POMIJANY
                          </Badge>
                        )}
                        {h.status === 'offline' && (
                          <Badge variant="outline" className="font-mono text-[9px] px-1 py-0">
                            OFFLINE
                          </Badge>
                        )}
                        {h.is_admin_panel && (
                          <Badge variant="default" className="font-mono text-[9px] px-1 py-0">
                            ADMIN
                          </Badge>
                        )}
                        {h.is_staging_env && (
                          <Badge variant="outline" className="font-mono text-[9px] px-1 py-0">
                            STAGING
                          </Badge>
                        )}
                      </div>
                    </label>
                  ))}
                {!searchingHosts && visibleHosts.length === 0 && (
                  <div className="text-center text-muted-foreground py-2 text-[11px]">
                    Brak hostów pasujących do filtra.
                  </div>
                )}
              </div>
            </div>

            {canExport ? (
              <Button onClick={handleExport} disabled={busy}>
                <Send className="h-3.5 w-3.5" />
                {busy
                  ? 'Eksportowanie...'
                  : dryRun
                  ? 'Generuj podgląd per Asset (Dry-Run)'
                  : 'Wyślij Assety do DefectDojo'}
              </Button>
            ) : (
              <p className="text-muted-foreground">
                Eksport do DefectDojo wymaga roli <code className="font-mono">modify_read</code> lub wyższej.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Podsumowanie i tabela Assetów po eksporcie / Dry-Run */}
      {exportResult && (
        <Card>
          <CardHeader className="pb-3 flex-row flex-wrap items-center justify-between gap-2 space-y-0">
            <div>
              <CardTitle className="text-sm">
                {exportResult.dry_run
                  ? 'Podgląd eksportu per IP Asset (Dry-Run)'
                  : 'Wynik eksportu do DefectDojo (1 IP = 1 Asset)'}
              </CardTitle>
              <CardDescription className="font-mono text-[11px]">
                Engagement: {exportResult.engagement_name} • Domyślna Organizacja: {exportResult.default_product_type_name} •
                close_old_findings: {String(exportResult.close_old_findings)}
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
              <Badge variant="secondary">Assety: {exportResult.stats.assets_to_export}</Badge>
              <Badge variant="secondary">Znaleziska: {exportResult.stats.total_findings}</Badge>
              {!exportResult.dry_run && (
                <>
                  <Badge variant="default">Nowe: {exportResult.stats.assets_created ?? 0}</Badge>
                  <Badge variant="outline">Zaktualizowane: {exportResult.stats.assets_updated ?? 0}</Badge>
                  {(exportResult.stats.assets_failed ?? 0) > 0 && (
                    <Badge variant="outline" className="border-destructive text-destructive">
                      Błędy: {exportResult.stats.assets_failed}
                    </Badge>
                  )}
                </>
              )}
              {(exportResult.stats.skipped_ignored_or_fp > 0 || exportResult.stats.skipped_offline > 0) && (
                <Badge variant="outline">
                  Pominięte: {exportResult.stats.skipped_ignored_or_fp} FP/ign, {exportResult.stats.skipped_offline} off
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {exportResult.dry_run && exportResult.assets && exportResult.assets.length > 0 && (
              <>
                {exportResult.assets_preview_truncated && (
                  <p className="text-xs text-muted-foreground font-mono">
                    Podgląd ograniczony do pierwszych {exportResult.assets_preview_limit} z {exportResult.stats.assets_to_export} Assetów.
                  </p>
                )}
                <div className="rounded-md border border-border overflow-x-auto max-h-72 overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Asset (IP)</TableHead>
                        <TableHead>Organizacja (Product Type)</TableHead>
                        <TableHead>Znaleziska</TableHead>
                        <TableHead>Przykładowe tytuły</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody className="text-xs">
                      {exportResult.assets.map((a) => (
                        <TableRow key={a.host_id}>
                          <TableCell className="font-mono font-semibold">
                            <div>{a.product_name}</div>
                            {a.hostname && <div className="text-[10px] font-normal text-muted-foreground">{a.hostname}</div>}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <span>{a.product_type_name}</span>
                              <Badge variant={a.product_type_source === 'owner_unit' ? 'default' : 'outline'} className="font-mono text-[9px]">
                                {a.product_type_source === 'owner_unit' ? 'owner_unit' : 'domyślna'}
                              </Badge>
                            </div>
                          </TableCell>
                          <TableCell className="font-mono">{a.findings_count}</TableCell>
                          <TableCell className="font-mono text-[11px] text-muted-foreground max-w-md truncate">
                            {a.payload.findings
                              .slice(0, 2)
                              .map((f) => String(f.title || ''))
                              .join(' • ')}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            )}

            {!exportResult.dry_run && exportResult.results && exportResult.results.length > 0 && (
              <div className="rounded-md border border-border overflow-x-auto max-h-72 overflow-y-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset (IP)</TableHead>
                      <TableHead>Organizacja</TableHead>
                      <TableHead>Znaleziska</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>ID w DefectDojo</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody className="text-xs">
                    {exportResult.results.map((r) => (
                      <TableRow key={r.host_id}>
                        <TableCell className="font-mono font-semibold">{r.product_name}</TableCell>
                        <TableCell>
                          {r.product_type_source === 'existing_in_defectdojo' ? (
                            <span className="text-muted-foreground italic">zachowana (istniejący Asset)</span>
                          ) : (
                            <span className="flex items-center gap-1.5">
                              <span>{r.product_type_name}</span>
                              <Badge variant={r.product_type_source === 'owner_unit' ? 'default' : 'outline'} className="font-mono text-[9px]">
                                {r.product_type_source === 'owner_unit' ? 'owner_unit' : 'domyślna'}
                              </Badge>
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="font-mono">{r.findings_count}</TableCell>
                        <TableCell>
                          {r.status === 'exported' ? (
                            <Badge variant={r.action === 'created' ? 'default' : 'secondary'} className="font-mono text-[10px]">
                              {r.action === 'created' ? 'UTWORZONY' : 'ZAKTUALIZOWANY'}
                            </Badge>
                          ) : (
                            <Badge
                              variant="outline"
                              className="border-destructive text-destructive font-mono text-[10px]"
                              title={r.error}
                            >
                              BŁĄD
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {r.status === 'exported'
                            ? `Product #${r.product_id ?? '?'} • Eng #${r.engagement_id ?? '?'} • Test #${r.test_id ?? '?'}`
                            : r.error}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            <details className="text-xs">
              <summary className="cursor-pointer font-mono text-muted-foreground hover:text-foreground">
                Pokaż surową odpowiedź JSON
              </summary>
              <pre className="mt-2 p-3 rounded-md bg-muted border border-border text-[11px] font-mono text-foreground overflow-x-auto max-h-96">
                {JSON.stringify(exportResult, null, 2)}
              </pre>
            </details>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
