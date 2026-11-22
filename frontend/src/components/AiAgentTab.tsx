import {
  AlertCircle,
  BellRing,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  KeyRound,
  Lock,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type {
  AiAgentConfig,
  AiAlertItem,
  AiAlertsResponse,
  AiUrgency,
  SignatureDraft,
  UserRole,
} from '../types';
import { formatTime } from './Badges';
import { HostDetailSheet } from './HostDetailSheet';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Switch } from './ui/checkbox';

interface Props {
  role: UserRole;
  isCurrentUserScoped?: boolean;
  alertsVersion?: number;
  onRefreshAll: () => void;
  onAlertsChanged?: () => void;
  onCreateSignature?: (draft: SignatureDraft) => void;
}

const CUSTOM_MODEL_VALUE = '__custom__';

const URGENCY_META: Record<AiUrgency, { label: string; variant: 'default' | 'secondary' | 'outline' }> = {
  critical: { label: 'CRITICAL', variant: 'default' },
  high: { label: 'HIGH', variant: 'default' },
  medium: { label: 'MEDIUM', variant: 'secondary' },
  low: { label: 'LOW', variant: 'outline' },
  safe: { label: 'BEZPIECZNY', variant: 'outline' },
};

export function AiAgentTab({
  role,
  isCurrentUserScoped = false,
  alertsVersion = 0,
  onRefreshAll,
  onAlertsChanged,
  onCreateSignature,
}: Props) {
  const [config, setConfig] = useState<AiAgentConfig | null>(null);
  const [loadingConfig, setLoadingConfig] = useState(true);

  // Formularz konfiguracji klucza OpenRouter (ekran startowy na środku + panel ustawień)
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [modelSelect, setModelSelect] = useState('google/gemini-2.5-flash');
  const [customModel, setCustomModel] = useState('');
  const [autoAfterScan, setAutoAfterScan] = useState(true);
  const [savingConfig, setSavingConfig] = useState(false);
  const [testingKey, setTestingKey] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // Alerty i analiza AI
  const [alertsData, setAlertsData] = useState<AiAlertsResponse | null>(null);
  const [analyzingAll, setAnalyzingAll] = useState(false);
  const [analyzingHostId, setAnalyzingHostId] = useState<string | null>(null);
  const [clearingAlerts, setClearingAlerts] = useState(false);
  const [filterMode, setFilterMode] = useState<'all' | 'urgent' | 'safe'>('all');
  const [search, setSearch] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);

  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canConfigure = hasPermission(role, 'manage_integrations') && !isCurrentUserScoped;
  const canAnalyze = hasPermission(role, 'modify');

  const loadConfig = useCallback(async () => {
    try {
      const cfg = await apiFetch<AiAgentConfig>('/ai-agent/config', role);
      setConfig(cfg);
      setAutoAfterScan(cfg.auto_analyze_after_scan);
      const isPopular = cfg.popular_models.some((m) => m.id === cfg.model_name);
      if (isPopular) {
        setModelSelect(cfg.model_name);
        setCustomModel('');
      } else {
        setModelSelect(CUSTOM_MODEL_VALUE);
        setCustomModel(cfg.model_name);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania konfiguracji AI Agenta');
    } finally {
      setLoadingConfig(false);
    }
  }, [role]);

  const loadAlerts = useCallback(async () => {
    try {
      const res = await apiFetch<AiAlertsResponse>('/ai-agent/alerts', role);
      setAlertsData(res);
    } catch {
      // ignore initial load error
    }
  }, [role]);

  useEffect(() => {
    loadConfig();
    loadAlerts();
  }, [loadConfig, loadAlerts]);

  useEffect(() => {
    if (alertsVersion > 0) {
      loadAlerts();
    }
  }, [alertsVersion, loadAlerts]);

  const effectiveModelName =
    modelSelect === CUSTOM_MODEL_VALUE ? customModel.trim() : modelSelect.trim();

  async function handleSaveConfig(e: React.FormEvent) {
    e.preventDefault();
    if (!canConfigure) return;
    if (!config?.configured && !apiKeyInput.trim()) {
      setError('Wklej swój klucz API z OpenRouter.');
      return;
    }
    if (!effectiveModelName) {
      setError('Podaj nazwę modelu OpenRouter (np. google/gemini-2.5-flash).');
      return;
    }

    setSavingConfig(true);
    setError(null);
    setNotice(null);
    try {
      const saved = await apiFetch<AiAgentConfig>('/ai-agent/config', role, {
        method: 'PUT',
        body: JSON.stringify({
          api_key: apiKeyInput.trim() || null,
          model_name: effectiveModelName,
          auto_analyze_after_scan: autoAfterScan,
          is_active: true,
        }),
      });
      setConfig(saved);
      setApiKeyInput('');
      setShowSettings(false);
      setNotice(
        `Zapisano klucz OpenRouter (zaszyfrowany AES-256-GCM) i aktywowano agenta (${saved.model_name}).`
      );
      await loadAlerts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu konfiguracji AI Agenta');
    } finally {
      setSavingConfig(false);
    }
  }

  async function handleToggleAutoScan(nextVal: boolean) {
    if (!canConfigure || !config) return;
    setAutoAfterScan(nextVal);
    setError(null);
    try {
      const saved = await apiFetch<AiAgentConfig>('/ai-agent/config', role, {
        method: 'PUT',
        body: JSON.stringify({
          model_name: config.model_name,
          auto_analyze_after_scan: nextVal,
          is_active: config.is_active,
        }),
      });
      setConfig(saved);
    } catch (err) {
      setAutoAfterScan(!nextVal);
      setError(err instanceof Error ? err.message : 'Nie udało się zmienić ustawienia auto-analizy');
    }
  }

  async function handleTestKey() {
    if (!canConfigure) return;
    setTestingKey(true);
    setError(null);
    setNotice(null);
    try {
      const res = await apiFetch<{ ok: boolean; error?: string; label?: string; model_name?: string }>(
        '/ai-agent/test',
        role,
        { method: 'POST' }
      );
      if (res.ok) {
        setNotice(
          `Połączenie z OpenRouter działa poprawnie (model: ${res.model_name}${res.label ? `, klucz: ${res.label}` : ''}).`
        );
      } else {
        setError(res.error || 'Klucz API OpenRouter nie przeszedł weryfikacji.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd testu połączenia z OpenRouter');
    } finally {
      setTestingKey(false);
    }
  }

  async function handleDeleteKey() {
    if (!canConfigure) return;
    setError(null);
    setNotice(null);
    try {
      await apiFetch('/ai-agent/config', role, { method: 'DELETE' });
      setShowSettings(false);
      setNotice('Usunięto zapisany klucz API OpenRouter.');
      await loadConfig();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania klucza API');
    }
  }

  async function handleAnalyzeAll() {
    if (!canAnalyze) return;
    setAnalyzingAll(true);
    setError(null);
    setNotice(null);
    try {
      const res = await apiFetch<{
        analyzed_count: number;
        urgent_alerts_count: number;
        fallback_count: number;
        warnings: string[];
      }>('/ai-agent/analyze', role, {
        method: 'POST',
        body: JSON.stringify({ max_hosts: 25 }),
      });
      if (res.warnings && res.warnings.length > 0) {
        setError(
          `Uwaga: dla ${res.fallback_count} hostów użyto deterministycznego fallbacku CVE/EOL (${res.warnings[0]}).`
        );
      }
      setNotice(
        `AI Agent przeanalizował ${res.analyzed_count} hostów — wykryto ${res.urgent_alerts_count} pilnych alertów wymagających reakcji administratora.`
      );
      await loadAlerts();
      onAlertsChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd uruchamiania analizy AI');
    } finally {
      setAnalyzingAll(false);
    }
  }

  async function handleAnalyzeSingleHost(hostId: string) {
    if (!canAnalyze) return;
    setAnalyzingHostId(hostId);
    setError(null);
    try {
      await apiFetch('/ai-agent/analyze', role, {
        method: 'POST',
        body: JSON.stringify({ host_ids: [hostId], max_hosts: 1 }),
      });
      await loadAlerts();
      onAlertsChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd analizy hosta');
    } finally {
      setAnalyzingHostId(null);
    }
  }

  async function handleAcknowledge(alert: AiAlertItem) {
    if (!canAnalyze) return;
    setError(null);
    try {
      await apiFetch(`/ai-agent/alerts/${alert.id}/acknowledge`, role, {
        method: 'PATCH',
        body: JSON.stringify({ acknowledged: !alert.acknowledged }),
      });
      await loadAlerts();
      onAlertsChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd aktualizacji statusu alertu');
    }
  }

  async function handleClearAlerts() {
    if (!canAnalyze) return;
    setClearingAlerts(true);
    setError(null);
    setNotice(null);
    try {
      const res = await apiFetch<{ deleted: number }>('/ai-agent/alerts', role, {
        method: 'DELETE',
      });
      setFilterMode('all');
      setSearch('');
      setNotice(
        `Wyczyszczono historię ocen AI (usunięto: ${res.deleted}). Zakładka jest gotowa do nowego skanu AI.`
      );
      await loadAlerts();
      onAlertsChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd resetowania wyników AI');
    } finally {
      setClearingAlerts(false);
    }
  }

  async function handleCopyAlert(alert: AiAlertItem) {
    const text =
      alert.admin_alert_message ||
      `[${alert.urgency.toUpperCase()}] ${alert.title}\n${alert.summary}\n${alert.remediation || ''}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(alert.id);
      setTimeout(() => setCopiedId((prev) => (prev === alert.id ? null : prev)), 1800);
    } catch {
      // ignore clipboard errors
    }
  }

  const handleCloseDetail = useCallback(() => {
    setSelectedHostId(null);
  }, []);

  const filteredAlerts = useMemo(() => {
    const list = alertsData?.alerts || [];
    const q = search.trim().toLowerCase();
    return list.filter((a) => {
      if (filterMode === 'urgent' && !a.requires_admin_alert) return false;
      if (filterMode === 'safe' && a.requires_admin_alert) return false;
      if (!q) return true;
      return (
        (a.ip_address || '').toLowerCase().includes(q) ||
        (a.hostname || '').toLowerCase().includes(q) ||
        (a.owner_unit || '').toLowerCase().includes(q) ||
        a.title.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.cves.some((c) => c.toLowerCase().includes(q)) ||
        a.affected_software.some((sw) => `${sw.name} ${sw.version || ''}`.toLowerCase().includes(q))
      );
    });
  }, [alertsData, filterMode, search]);

  if (loadingConfig) {
    return (
      <div className="py-16 text-center text-xs font-mono text-muted-foreground">
        Ładowanie AI Security Agenta...
      </div>
    );
  }

  // EKRAN STARTOWY NA ŚRODKU: gdy brak zapisanego klucza API OpenRouter
  if (!config?.configured) {
    return (
      <div className="py-8 flex flex-col items-center justify-center">
        <Card className="w-full max-w-lg">
          <CardHeader className="text-center space-y-2 pb-4">
            <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full border border-border bg-muted">
              <Bot className="h-5 w-5 text-foreground" />
            </div>
            <div className="flex items-center justify-center gap-1.5">
              <Badge variant="secondary" className="font-mono text-[10px]">
                OpenRouter
              </Badge>
              <Badge variant="outline" className="font-mono text-[10px] gap-1">
                <Lock className="h-2.5 w-2.5" />
                TRYB READ-ONLY
              </Badge>
            </div>
            <CardTitle className="text-lg">AI Security Agent</CardTitle>
            <CardDescription className="text-xs leading-relaxed">
              Podaj klucz API OpenRouter — zostanie zapisany od razu (szyfrowany AES-256-GCM). Agent niczego nie
              modyfikuje w systemie: po skanie sprawdza wykryte wersje frameworków i usług oraz alarmuje
              administratora, gdy któryś host jest podatny.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <AlertDescription className="text-foreground">{error}</AlertDescription>
              </Alert>
            )}
            {notice && (
              <Alert>
                <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
                <AlertDescription className="text-foreground">{notice}</AlertDescription>
              </Alert>
            )}

            {canConfigure ? (
              <form onSubmit={handleSaveConfig} className="space-y-3.5 text-xs">
                <label className="block space-y-1.5">
                  <span className="text-muted-foreground font-medium">Klucz API OpenRouter</span>
                  <Input
                    required
                    autoFocus
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder="sk-or-v1-..."
                    className="font-mono"
                  />
                </label>

                <label className="block space-y-1.5">
                  <span className="text-muted-foreground font-medium">Model AI (OpenRouter)</span>
                  <Select
                    value={modelSelect}
                    onChange={(e) => setModelSelect(e.target.value)}
                    className="font-mono"
                  >
                    {(config?.popular_models || []).map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.label} ({m.id})
                      </option>
                    ))}
                    <option value={CUSTOM_MODEL_VALUE}>Własny model OpenRouter...</option>
                  </Select>
                </label>

                {modelSelect === CUSTOM_MODEL_VALUE && (
                  <label className="block space-y-1.5">
                    <span className="text-muted-foreground">Slug modelu OpenRouter</span>
                    <Input
                      required
                      value={customModel}
                      onChange={(e) => setCustomModel(e.target.value)}
                      placeholder="np. google/gemini-2.5-flash"
                      className="font-mono"
                    />
                  </label>
                )}

                <div className="flex items-center justify-between rounded-md border border-border bg-muted/25 px-3 py-2">
                  <div className="space-y-0.5">
                    <div className="font-medium text-foreground">Automatycznie sprawdzaj po skanie</div>
                    <div className="text-[11px] text-muted-foreground">
                      Po zakończeniu skanu agent sprawdzi nowe hosty i przygotuje alerty.
                    </div>
                  </div>
                  <Switch checked={autoAfterScan} onCheckedChange={(v) => setAutoAfterScan(Boolean(v))} />
                </div>

                <Button type="submit" disabled={savingConfig || !apiKeyInput.trim()} className="w-full">
                  <KeyRound className="h-3.5 w-3.5" />
                  {savingConfig ? 'Zapisywanie klucza...' : 'Zapisz klucz API i uruchom agenta'}
                </Button>
              </form>
            ) : (
              <div className="rounded-md border border-border bg-muted/30 p-3 text-center text-xs text-muted-foreground">
                AI Security Agent nie został jeszcze skonfigurowany. Podanie klucza API OpenRouter wymaga pełnego konta{' '}
                <code className="font-mono text-foreground">admin</code>.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  const summary = alertsData?.summary ?? {
    total: 0,
    urgent_unacknowledged: 0,
    vulnerable_or_outdated: 0,
    safe_or_low: 0,
  };

  return (
    <div className="space-y-5">
      {/* Pasek statusu i sterowania AI Agenta */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="default" className="font-mono gap-1.5">
            <Bot className="h-3 w-3" />
            <span>OpenRouter: {config.model_name}</span>
          </Badge>
          <Badge variant="outline" className="font-mono text-[10px] gap-1">
            <Lock className="h-2.5 w-2.5" />
            READ-ONLY (bez modyfikacji)
          </Badge>
          {canConfigure && (
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground pl-1 cursor-pointer">
              <Switch checked={autoAfterScan} onCheckedChange={handleToggleAutoScan} />
              <span>Auto po skanie</span>
            </label>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {canAnalyze && (
            <Button size="sm" onClick={handleAnalyzeAll} disabled={analyzingAll || clearingAlerts}>
              <Sparkles className="h-3.5 w-3.5" />
              {analyzingAll ? 'Analizowanie hostów...' : 'Sprawdź wszystkie hosty z AI'}
            </Button>
          )}
          {canAnalyze && summary.total > 0 && (
            <Button
              size="sm"
              variant="outline"
              onClick={handleClearAlerts}
              disabled={clearingAlerts || analyzingAll}
              title="Wyczyść wszystkie obecne oceny i alerty AI (bez usuwania klucza API)"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              {clearingAlerts ? 'Czyszczenie...' : 'Resetuj wyniki'}
            </Button>
          )}
          {canConfigure && (
            <Button
              size="sm"
              variant={showSettings ? 'default' : 'outline'}
              onClick={() => setShowSettings((v) => !v)}
            >
              <Settings className="h-3.5 w-3.5" />
              Klucz / Model
            </Button>
          )}
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

      {/* Rozwijane ustawienia klucza i modelu */}
      {canConfigure && showSettings && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-muted-foreground" />
              Konfiguracja OpenRouter (klucz zaszyfrowany AES-256-GCM)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSaveConfig} className="grid grid-cols-1 md:grid-cols-12 gap-3 text-xs items-end">
              <label className="space-y-1 md:col-span-4">
                <span className="text-muted-foreground">Nowy klucz API (zostaw puste, aby zachować obecny)</span>
                <Input
                  type="password"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder="sk-or-v1-... (zapisany)"
                  className="font-mono"
                />
              </label>
              <label className="space-y-1 md:col-span-4">
                <span className="text-muted-foreground">Model OpenRouter</span>
                <Select
                  value={modelSelect}
                  onChange={(e) => setModelSelect(e.target.value)}
                  className="font-mono"
                >
                  {(config.popular_models || []).map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.label} ({m.id})
                    </option>
                  ))}
                  <option value={CUSTOM_MODEL_VALUE}>Własny model OpenRouter...</option>
                </Select>
              </label>
              {modelSelect === CUSTOM_MODEL_VALUE && (
                <label className="space-y-1 md:col-span-4">
                  <span className="text-muted-foreground">Własny slug modelu</span>
                  <Input
                    required
                    value={customModel}
                    onChange={(e) => setCustomModel(e.target.value)}
                    placeholder="np. google/gemini-2.5-flash"
                    className="font-mono"
                  />
                </label>
              )}
              <div className="flex flex-wrap gap-1.5 md:col-span-4">
                <Button type="submit" size="sm" disabled={savingConfig}>
                  {savingConfig ? 'Zapis...' : 'Zapisz'}
                </Button>
                <Button type="button" size="sm" variant="outline" disabled={testingKey} onClick={handleTestKey}>
                  {testingKey ? 'Test...' : 'Testuj klucz'}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={handleDeleteKey}
                  title="Usuń zapisany klucz API"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Usuń klucz
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Karty KPI AI Agenta */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">
              Pilne alerty dla admina
            </CardDescription>
            <BellRing className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{summary.urgent_unacknowledged}</div>
            <div className="text-[11px] text-muted-foreground">niepotwierdzone, wymagające reakcji</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">
              Podatne / przestarzałe wersje
            </CardDescription>
            <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{summary.vulnerable_or_outdated}</div>
            <div className="text-[11px] text-muted-foreground">hosty z ryzykiem critical / high / medium</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-4 pb-1.5 flex-row items-center justify-between space-y-0">
            <CardDescription className="uppercase tracking-wider text-[11px]">
              Zweryfikowane jako bezpieczne
            </CardDescription>
            <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" />
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="text-2xl font-bold font-mono text-foreground">{summary.safe_or_low}</div>
            <div className="text-[11px] text-muted-foreground">brak znanych podatnych wersji</div>
          </CardContent>
        </Card>
      </div>

      {/* Pasek filtrów */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Szukaj po IP, frameworku, CVE, jednostce..."
            className="pl-8"
          />
        </div>
        <div className="flex items-center gap-1.5">
          {(
            [
              ['all', `Wszystkie (${summary.total})`],
              ['urgent', `Pilne alerty (${(alertsData?.alerts || []).filter((a) => a.requires_admin_alert).length})`],
              ['safe', `Bezpieczne / pozostałe (${(alertsData?.alerts || []).filter((a) => !a.requires_admin_alert).length})`],
            ] as const
          ).map(([k, lbl]) => (
            <Button
              key={k}
              size="sm"
              variant={filterMode === k ? 'default' : 'outline'}
              onClick={() => setFilterMode(k)}
              className="text-xs"
            >
              {lbl}
            </Button>
          ))}
        </div>
      </div>

      {/* Lista ocen i alertów per host */}
      {filteredAlerts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center space-y-3">
            <Bot className="h-8 w-8 mx-auto text-muted-foreground" />
            <div className="space-y-1">
              <p className="text-sm font-medium text-foreground">
                {summary.total === 0
                  ? 'Brak jeszcze ocen AI dla wykrytych hostów.'
                  : 'Brak alertów pasujących do wybranego filtra.'}
              </p>
              <p className="text-xs text-muted-foreground">
                {summary.total === 0
                  ? 'Kliknij „Sprawdź wszystkie hosty z AI” powyżej, aby sprawdzić wersje usług i wygenerować alerty.'
                  : 'Zmień filtr lub frazę wyszukiwania.'}
              </p>
            </div>
            {summary.total === 0 && canAnalyze && (
              <Button size="sm" onClick={handleAnalyzeAll} disabled={analyzingAll}>
                <Sparkles className="h-3.5 w-3.5" />
                {analyzingAll ? 'Analizowanie...' : 'Sprawdź wszystkie hosty z AI'}
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filteredAlerts.map((alert) => {
            const meta = URGENCY_META[alert.urgency] || URGENCY_META.safe;
            const isReanalyzing = analyzingHostId === alert.host_id;
            return (
              <Card
                key={alert.id}
                className={
                  alert.requires_admin_alert && !alert.acknowledged
                    ? 'border-foreground/40'
                    : alert.acknowledged
                    ? 'opacity-75'
                    : undefined
                }
              >
                <CardContent className="p-4 space-y-3 text-xs">
                  {/* Nagłówek karty alertu */}
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {alert.requires_admin_alert && !alert.acknowledged && (
                          <Badge variant="default" className="font-mono text-[10px] gap-1">
                            <BellRing className="h-2.5 w-2.5" />
                            ALARMUJ ADMINA
                          </Badge>
                        )}
                        <Badge variant={meta.variant} className="font-mono text-[10px]">
                          {meta.label}
                        </Badge>
                        {alert.acknowledged && (
                          <Badge variant="outline" className="font-mono text-[10px] gap-1">
                            <CheckCircle2 className="h-2.5 w-2.5" />
                            Potwierdzono{alert.acknowledged_by ? ` (${alert.acknowledged_by})` : ''}
                          </Badge>
                        )}
                        <button
                          type="button"
                          onClick={() => setSelectedHostId(alert.host_id)}
                          className="font-mono font-semibold text-sm text-foreground underline underline-offset-2 hover:opacity-80"
                        >
                          {alert.ip_address || alert.host_id.slice(0, 8)}
                        </button>
                        {(alert.custom_label || alert.hostname) && (
                          <span className="text-muted-foreground">
                            ({alert.custom_label || alert.hostname})
                          </span>
                        )}
                        {alert.owner_unit && (
                          <Badge variant="secondary" className="font-mono text-[10px]">
                            {alert.owner_unit}
                          </Badge>
                        )}
                      </div>
                      <div className="font-medium text-sm text-foreground">{alert.title}</div>
                    </div>

                    <div className="flex flex-col items-end gap-1 shrink-0 font-mono text-[10px] text-muted-foreground">
                      <span>{formatTime(alert.created_at)}</span>
                      <Badge variant="outline" className="font-mono text-[9px] px-1.5 py-0">
                        {alert.analysis_source}
                      </Badge>
                    </div>
                  </div>

                  {/* Wykryte oprogramowanie i CVE */}
                  {(alert.affected_software.length > 0 || alert.cves.length > 0) && (
                    <div className="flex flex-wrap gap-1.5">
                      {alert.affected_software.map((sw, idx) => (
                        <Badge
                          key={`${sw.name}-${sw.version || ''}-${idx}`}
                          variant={sw.status === 'safe' ? 'outline' : 'secondary'}
                          className="font-mono text-[10px]"
                          title={sw.reason}
                        >
                          {sw.name}
                          {sw.version ? ` ${sw.version}` : ''}
                          {sw.port ? ` :${sw.port}` : ''} [{sw.status}]
                        </Badge>
                      ))}
                      {alert.cves.map((cve) => (
                        <Badge key={cve} variant="default" className="font-mono text-[10px]">
                          {cve}
                        </Badge>
                      ))}
                    </div>
                  )}

                  {/* Ocena AI */}
                  <p className="text-foreground leading-relaxed">{alert.summary}</p>

                  {/* Gotowy alert do administratora */}
                  {alert.admin_alert_message && (
                    <div className="rounded-md border border-border bg-muted/40 p-3 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] uppercase tracking-wider font-semibold text-muted-foreground flex items-center gap-1">
                          <BellRing className="h-3 w-3" />
                          Gotowy alert do administratora
                        </span>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-[10px]"
                          onClick={() => handleCopyAlert(alert)}
                        >
                          {copiedId === alert.id ? (
                            <>
                              <Check className="h-3 w-3" />
                              Skopiowano
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              Kopiuj alert
                            </>
                          )}
                        </Button>
                      </div>
                      <p className="font-mono text-[11px] text-foreground leading-relaxed">
                        {alert.admin_alert_message}
                      </p>
                    </div>
                  )}

                  {/* Rekomendacja */}
                  {alert.remediation && (
                    <div className="text-[11px] text-muted-foreground">
                      <span className="font-medium text-foreground">Rekomendacja:</span> {alert.remediation}
                    </div>
                  )}

                  {/* Akcje */}
                  <div className="pt-2 border-t border-border/60 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => setSelectedHostId(alert.host_id)}
                      >
                        <Server className="h-3 w-3" />
                        Szczegóły hosta
                      </Button>
                      {canAnalyze && (
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          className="h-7 text-xs"
                          disabled={isReanalyzing || analyzingAll}
                          onClick={() => handleAnalyzeSingleHost(alert.host_id)}
                        >
                          <RefreshCw className={`h-3 w-3 ${isReanalyzing ? 'animate-spin' : ''}`} />
                          {isReanalyzing ? 'Analiza...' : 'Sprawdź ponownie'}
                        </Button>
                      )}
                    </div>

                    {canAnalyze && alert.requires_admin_alert && (
                      <Button
                        type="button"
                        size="sm"
                        variant={alert.acknowledged ? 'outline' : 'default'}
                        className="h-7 text-xs"
                        onClick={() => handleAcknowledge(alert)}
                      >
                        <CheckCircle2 className="h-3 w-3" />
                        {alert.acknowledged ? 'Cofnij potwierdzenie' : 'Oznacz: zaalarmowano admina'}
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Prawy panel szczegółów hosta po kliknięciu hosta w AI Agent */}
      <HostDetailSheet
        hostId={selectedHostId}
        onClose={handleCloseDetail}
        role={role}
        onRefresh={() => {
          onRefreshAll();
          loadAlerts();
        }}
        onCreateSignature={onCreateSignature}
        onError={setError}
      />
    </div>
  );
}
