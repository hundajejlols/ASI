import { AlertCircle, CheckCircle2, Plug, Send, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type { DefectDojoConfig, HostSummary, UserRole } from '../types';
import { formatTime } from './Badges';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Checkbox } from './ui/checkbox';
import { Input } from './ui/input';

interface Props {
  role: UserRole;
  hosts?: HostSummary[];
}

export function DefectDojoTab({ role, hosts = [] }: Props) {
  const [config, setConfig] = useState<DefectDojoConfig | null>(null);
  const [baseUrl, setBaseUrl] = useState('');
  const [engagementId, setEngagementId] = useState('1');
  const [productName, setProductName] = useState('AGH Attack Surface');
  const [verifyTls, setVerifyTls] = useState(true);
  const [apiToken, setApiToken] = useState('');

  const [onlyInteresting, setOnlyInteresting] = useState(false);
  const [closeOldFindings, setCloseOldFindings] = useState(false);
  const [dryRun, setDryRun] = useState(true);
  const [selectedHostIds, setSelectedHostIds] = useState<string[]>([]);

  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null);
  const [exportResult, setExportResult] = useState<Record<string, unknown> | null>(null);
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
      if (data.engagement_id) setEngagementId(String(data.engagement_id));
      if (data.product_name) setProductName(data.product_name);
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
  }, [role]);

  async function handleSaveConfig(e: React.FormEvent) {
    e.preventDefault();
    if (!isAdmin) return;
    setError(null);
    setNotice(null);
    setSavingConfig(true);
    try {
      const payload: Record<string, unknown> = {
        base_url: baseUrl.trim(),
        engagement_id: Number(engagementId),
        product_name: productName.trim() || null,
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
      setNotice('Konfiguracja DefectDojo zapisana (token zaszyfrowany AES-256-GCM).');
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
      const res = await apiFetch<Record<string, unknown>>('/integrations/defectdojo/export', role, {
        method: 'POST',
        body: JSON.stringify(bodyPayload),
      });
      setExportResult(res);
      if (dryRun) {
        setNotice('Wygenerowano podgląd raportu Generic Findings Import (Dry-Run).');
      } else {
        setNotice('Pomyślnie wyeksportowano znaleziska do DefectDojo API v2.');
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
              <CardTitle>Konfiguracja DefectDojo API v2</CardTitle>
              <CardDescription>
                Token API: {config?.has_api_token ? 'Zapisany (AES-256-GCM, ukryty)' : 'Brak'}
                {config?.updated_at ? ` • ${formatTime(config.updated_at)}` : ''}
              </CardDescription>
            </div>
            <Badge variant={config?.configured ? 'default' : 'outline'} className="font-mono">
              {config?.configured ? 'Skonfigurowane' : 'Nieskonfigurowane'}
            </Badge>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSaveConfig} className="space-y-3 text-xs">
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

              <div className="grid grid-cols-2 gap-3">
                <label className="space-y-1">
                  <span className="text-muted-foreground">Engagement ID</span>
                  <Input
                    type="number"
                    min={1}
                    disabled={!isAdmin}
                    value={engagementId}
                    onChange={(e) => setEngagementId(e.target.value)}
                    className="font-mono"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-muted-foreground">Product Name</span>
                  <Input
                    disabled={!isAdmin}
                    value={productName}
                    onChange={(e) => setProductName(e.target.value)}
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
                    placeholder="Token API v2"
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
            <CardTitle>Eksport (Generic Findings Import)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <div className="space-y-2.5 text-foreground">
              <label className="flex items-center gap-2 cursor-pointer">
                <Checkbox
                  disabled={!canExport}
                  checked={onlyInteresting}
                  onCheckedChange={(v) => setOnlyInteresting(Boolean(v))}
                />
                <span>Tylko istotne znaleziska (sygnatury, admin, staging, Diff)</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <Checkbox
                  disabled={!canExport}
                  checked={closeOldFindings}
                  onCheckedChange={(v) => setCloseOldFindings(Boolean(v))}
                />
                <span>Zamknij stare/ignorowane znaleziska przy reimporcie (close_old_findings)</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <Checkbox
                  disabled={!canExport}
                  checked={dryRun}
                  onCheckedChange={(v) => setDryRun(Boolean(v))}
                />
                <span>Dry-Run (podgląd JSON bez wysyłki HTTP)</span>
              </label>
            </div>

            {hosts.length > 0 && (
              <div className="space-y-2 border-t border-border pt-3">
                <div className="flex items-center justify-between text-muted-foreground">
                  <span>
                    Wybierz hosty do eksportu ({selectedHostIds.length === 0 ? 'wszystkie' : selectedHostIds.length}):
                  </span>
                  {canExport && selectedHostIds.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setSelectedHostIds([])}
                      className="text-[11px] underline hover:text-foreground"
                    >
                      Wyczyść filtr (wszystkie)
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-1.5 max-h-36 overflow-y-auto p-2 rounded-md bg-muted/50 border border-border">
                  {hosts.map((h) => (
                    <label key={h.id} className="flex items-center justify-between gap-2 cursor-pointer">
                      <div className="flex items-center gap-2">
                        <Checkbox
                          disabled={!canExport}
                          checked={selectedHostIds.includes(h.id)}
                          onCheckedChange={(v) => toggleHostSelection(h.id, Boolean(v))}
                        />
                        <span className="font-mono text-foreground">{h.ip_address}</span>
                        <span className="text-muted-foreground truncate">
                          {h.override?.custom_label || h.hostname || ''}
                        </span>
                      </div>
                      <div className="flex items-center gap-1">
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
                </div>
              </div>
            )}

            {canExport ? (
              <Button onClick={handleExport} disabled={busy}>
                <Send className="h-3.5 w-3.5" />
                {busy ? 'Generowanie...' : dryRun ? 'Generuj podgląd (Dry-Run)' : 'Wyślij do DefectDojo'}
              </Button>
            ) : (
              <p className="text-muted-foreground">
                Eksport do DefectDojo wymaga roli <code className="font-mono">modify_read</code> lub wyższej.
              </p>
            )}

            {exportResult && (
              <pre className="p-3 rounded-md bg-muted border border-border text-[11px] font-mono text-foreground overflow-x-auto max-h-96">
                {JSON.stringify(exportResult, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
