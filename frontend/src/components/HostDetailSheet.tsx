import {
  AlertCircle,
  BellRing,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Edit3,
  Lock,
  Plus,
  Sparkles,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type {
  AiAgentConfig,
  AiAlertItem,
  AiAlertsResponse,
  HostDetail,
  ServiceOut,
  Severity,
  SignatureDraft,
  UserRole,
} from '../types';
import { formatTime, HostStatusBadge, SeverityBadge } from './Badges';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent } from './ui/card';
import { Checkbox } from './ui/checkbox';
import { Input } from './ui/input';
import { ScrollArea } from './ui/scroll-area';
import { Select } from './ui/select';
import { Separator } from './ui/separator';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from './ui/sheet';
import { Textarea } from './ui/textarea';

interface Props {
  hostId: string | null;
  onClose: () => void;
  role: UserRole;
  onRefresh: () => void;
  onAlertsChanged?: () => void;
  onCreateSignature?: (draft: SignatureDraft) => void;
  onError?: (message: string) => void;
}

export function HostDetailSheet({
  hostId,
  onClose,
  role,
  onRefresh,
  onAlertsChanged,
  onCreateSignature,
  onError,
}: Props) {
  const [selectedHost, setSelectedHost] = useState<HostDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [expandedHeaders, setExpandedHeaders] = useState<Record<string, boolean>>({});

  // Formularz asset_overrides dla hosta
  const [customLabel, setCustomLabel] = useState('');
  const [ownerUnit, setOwnerUnit] = useState('');
  const [criticality, setCriticality] = useState<string>('');
  const [tagsInput, setTagsInput] = useState('');
  const [notes, setNotes] = useState('');
  const [isIgnored, setIsIgnored] = useState(false);
  const [isFalsePositive, setIsFalsePositive] = useState(false);
  const [savingOverride, setSavingOverride] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Edycja asset_overrides dla pojedynczej usługi (entity_type: 'service')
  const [editingSvcId, setEditingSvcId] = useState<string | null>(null);
  const [svcLabel, setSvcLabel] = useState('');
  const [svcNotes, setSvcNotes] = useState('');
  const [svcIgnored, setSvcIgnored] = useState(false);
  const [svcFp, setSvcFp] = useState(false);
  const [savingSvcOv, setSavingSvcOv] = useState(false);

  // Pasywna ocena AI Security Agenta dla wybranego hosta (read-only)
  const [aiConfigured, setAiConfigured] = useState(false);
  const [aiAlert, setAiAlert] = useState<AiAlertItem | null>(null);
  const [analyzingAi, setAnalyzingAi] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const canAdd = hasPermission(role, 'add');
  const canModify = hasPermission(role, 'modify');

  const fetchHostDetail = useCallback(
    async (id: string, preserveNotice = false) => {
      setLoadingDetail(true);
      if (!preserveNotice) setSaveMessage(null);
      setSaveError(null);
      setEditingSvcId(null);
      try {
        const detail = await apiFetch<HostDetail>(`/hosts/${id}`, role);
        setSelectedHost(detail);
        setCustomLabel(detail.override?.custom_label || '');
        setOwnerUnit(detail.override?.owner_unit || '');
        setCriticality(detail.override?.criticality || '');
        setTagsInput((detail.override?.tags || []).join(', '));
        setNotes(detail.override?.notes || '');
        setIsIgnored(detail.override?.is_ignored || false);
        setIsFalsePositive(detail.override?.is_false_positive || false);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'Błąd ładowania szczegółów hosta';
        setSelectedHost(null);
        onError?.(msg);
        onClose();
      } finally {
        setLoadingDetail(false);
      }
    },
    [role, onClose, onError]
  );

  useEffect(() => {
    if (!hostId) {
      setSelectedHost(null);
      setExpandedHeaders({});
      setEditingSvcId(null);
      setSaveMessage(null);
      setSaveError(null);
      setAiAlert(null);
      setAiError(null);
      return;
    }
    fetchHostDetail(hostId);
    Promise.all([
      apiFetch<AiAgentConfig>('/ai-agent/config', role).catch(() => null),
      apiFetch<AiAlertsResponse>(`/ai-agent/alerts?host_id=${hostId}`, role).catch(() => null),
    ]).then(([cfg, al]) => {
      setAiConfigured(Boolean(cfg?.configured && cfg?.is_active));
      setAiAlert(al?.alerts?.[0] ?? null);
      setAiError(null);
    });
  }, [hostId, role, fetchHostDetail]);

  async function handleAnalyzeThisHost() {
    if (!selectedHost || !canModify) return;
    setAnalyzingAi(true);
    setAiError(null);
    try {
      const res = await apiFetch<{ alerts: AiAlertItem[]; warnings?: string[] }>('/ai-agent/analyze', role, {
        method: 'POST',
        body: JSON.stringify({ host_ids: [selectedHost.id], max_hosts: 1 }),
      });
      if (res.alerts?.[0]) {
        setAiAlert(res.alerts[0]);
        onAlertsChanged?.();
      }
      if (res.warnings && res.warnings.length > 0) {
        setAiError(`Użyto deterministycznego fallbacku CVE/EOL (${res.warnings[0]}).`);
      }
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'Błąd analizy AI dla hosta');
    } finally {
      setAnalyzingAi(false);
    }
  }

  async function handleSaveOverride(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedHost || !canModify) return;
    setSavingOverride(true);
    setSaveMessage(null);
    setSaveError(null);
    try {
      const tags = tagsInput
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      await apiFetch('/overrides', role, {
        method: 'PATCH',
        body: JSON.stringify({
          entity_type: 'host',
          entity_id: selectedHost.id,
          custom_label: customLabel || null,
          owner_unit: ownerUnit || null,
          criticality: (criticality || null) as Severity | null,
          tags,
          notes: notes || null,
          is_ignored: isIgnored,
          is_false_positive: isFalsePositive,
        }),
      });
      setSaveMessage('Zapisano nadpisanie hosta (notatka zaszyfrowana AES-256-GCM + AAD).');
      await fetchHostDetail(selectedHost.id, true);
      onRefresh();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Błąd zapisu nadpisania');
    } finally {
      setSavingOverride(false);
    }
  }

  function startEditServiceOverride(svc: ServiceOut) {
    setEditingSvcId(svc.id);
    setSvcLabel(svc.override?.custom_label || '');
    setSvcNotes(svc.override?.notes || '');
    setSvcIgnored(svc.override?.is_ignored || false);
    setSvcFp(svc.override?.is_false_positive || false);
  }

  async function handleSaveServiceOverride(svcId: string) {
    if (!selectedHost || !canModify) return;
    setSavingSvcOv(true);
    setSaveError(null);
    try {
      await apiFetch('/overrides', role, {
        method: 'PATCH',
        body: JSON.stringify({
          entity_type: 'service',
          entity_id: svcId,
          custom_label: svcLabel || null,
          notes: svcNotes || null,
          is_ignored: svcIgnored,
          is_false_positive: svcFp,
        }),
      });
      setEditingSvcId(null);
      setSaveMessage('Zapisano nadpisanie usługi (asset_overrides: service).');
      await fetchHostDetail(selectedHost.id, true);
      onRefresh();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Błąd zapisu nadpisania usługi');
    } finally {
      setSavingSvcOv(false);
    }
  }

  const sheetOpen = Boolean(hostId || selectedHost || loadingDetail);

  return (
    <Sheet open={sheetOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent>
        <SheetHeader className="pb-4">
          <div className="flex items-center gap-3">
            <SheetTitle className="font-mono text-lg">
              {selectedHost?.ip_address || 'Ładowanie...'}
            </SheetTitle>
            {selectedHost && (
              <HostStatusBadge status={selectedHost.status} missedScans={selectedHost.missed_scans} />
            )}
          </div>
          <SheetDescription className="font-mono">
            {selectedHost?.hostname || 'Brak nazwy DNS'}
          </SheetDescription>
        </SheetHeader>

        <Separator />

        <ScrollArea className="flex-1 pr-3 mt-4">
          {selectedHost && (
            <div className="space-y-6 pb-6">
              {/* Pasywna ocena AI Security Agenta (READ-ONLY) */}
              <div className="rounded-lg border border-border bg-muted/25 p-3.5 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-[11px] text-foreground">
                    <Bot className="h-3.5 w-3.5 text-muted-foreground" />
                    <span>AI Security Agent (Read-Only)</span>
                  </div>
                  {canModify && aiConfigured && (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      className="h-6 px-2 text-[10px]"
                      disabled={analyzingAi}
                      onClick={handleAnalyzeThisHost}
                    >
                      <Sparkles className="h-3 w-3" />
                      {analyzingAi ? 'Sprawdzanie...' : aiAlert ? 'Sprawdź ponownie' : 'Analizuj z AI'}
                    </Button>
                  )}
                </div>

                {aiError && (
                  <p className="font-mono text-[11px] text-muted-foreground">{aiError}</p>
                )}

                {aiAlert ? (
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {aiAlert.requires_admin_alert && (
                        <Badge variant="default" className="font-mono text-[10px] gap-1">
                          <BellRing className="h-2.5 w-2.5" />
                          ALARMUJ ADMINA
                        </Badge>
                      )}
                      <Badge
                        variant={
                          aiAlert.urgency === 'critical' || aiAlert.urgency === 'high'
                            ? 'default'
                            : aiAlert.urgency === 'medium'
                            ? 'secondary'
                            : 'outline'
                        }
                        className="font-mono uppercase text-[10px]"
                      >
                        {aiAlert.urgency === 'safe' ? 'BEZPIECZNY' : aiAlert.urgency}
                      </Badge>
                      {aiAlert.cves.map((cve) => (
                        <Badge key={cve} variant="secondary" className="font-mono text-[10px]">
                          {cve}
                        </Badge>
                      ))}
                      <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                        {aiAlert.analysis_source}
                      </span>
                    </div>
                    <div className="font-medium text-foreground">{aiAlert.title}</div>
                    <p className="text-muted-foreground leading-relaxed">{aiAlert.summary}</p>
                    {aiAlert.admin_alert_message && (
                      <div className="rounded border border-border bg-background p-2 font-mono text-[11px] text-foreground">
                        {aiAlert.admin_alert_message}
                      </div>
                    )}
                    {aiAlert.remediation && (
                      <div className="text-[11px] text-muted-foreground">
                        <span className="font-medium text-foreground">Rekomendacja:</span> {aiAlert.remediation}
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-[11px] text-muted-foreground">
                    {aiConfigured
                      ? 'Ten host nie był jeszcze sprawdzany przez AI Agenta. Kliknij „Analizuj z AI”, aby zweryfikować wersje wykrytych usług.'
                      : 'Skonfiguruj klucz API OpenRouter w zakładce AI Agent, aby sprawdzać wersje usług na tym hoście.'}
                  </p>
                )}
              </div>

              {/* Wykryte usługi */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Wykryte usługi ({selectedHost.services.length})
                </h4>
                {selectedHost.services.map((svc) => {
                  const fp = svc.latest_http_fingerprint;
                  const showHdr = !!expandedHeaders[svc.id];
                  const isEditingSvc = editingSvcId === svc.id;
                  return (
                    <Card key={svc.id}>
                      <CardContent className="p-4 space-y-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="font-mono text-sm font-semibold text-foreground">
                            {svc.port}/{svc.protocol}{' '}
                            <span className="text-muted-foreground font-normal">
                              {svc.service_name || 'unknown'} {svc.product || ''} {svc.version || ''}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            {svc.override?.is_ignored && (
                              <Badge variant="outline" className="font-mono uppercase text-[10px]">
                                ignored
                              </Badge>
                            )}
                            {svc.override?.is_false_positive && (
                              <Badge variant="secondary" className="font-mono uppercase text-[10px]">
                                FP
                              </Badge>
                            )}
                            <Badge
                              variant={svc.state === 'open' ? 'default' : 'outline'}
                              className="font-mono uppercase text-[10px]"
                            >
                              {svc.state}
                            </Badge>
                            {canModify && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-6 px-2 text-[10px]"
                                onClick={() => (isEditingSvc ? setEditingSvcId(null) : startEditServiceOverride(svc))}
                              >
                                <Edit3 className="h-3 w-3" />
                                Override
                              </Button>
                            )}
                          </div>
                        </div>

                        {svc.override && !isEditingSvc && (
                          <div className="text-[11px] p-2 rounded bg-muted/60 border border-border space-y-0.5">
                            {svc.override.custom_label && (
                              <div>
                                <span className="text-muted-foreground">Etykieta usługi:</span>{' '}
                                {svc.override.custom_label}
                              </div>
                            )}
                            {svc.override.notes && (
                              <div>
                                <span className="text-muted-foreground">Notatka (AES-GCM):</span>{' '}
                                {svc.override.notes}
                              </div>
                            )}
                          </div>
                        )}

                        {isEditingSvc && canModify && (
                          <div className="p-3 rounded-md border border-border bg-muted/40 space-y-2 text-xs">
                            <Input
                              value={svcLabel}
                              onChange={(e) => setSvcLabel(e.target.value)}
                              placeholder="Etykieta usługi (opcjonalnie)"
                            />
                            <Textarea
                              rows={2}
                              value={svcNotes}
                              onChange={(e) => setSvcNotes(e.target.value)}
                              placeholder="Notatka usługi (szyfrowana AES-256-GCM)"
                            />
                            <div className="flex flex-wrap items-center gap-4">
                              <label className="flex items-center gap-1.5 cursor-pointer">
                                <Checkbox checked={svcIgnored} onCheckedChange={(v) => setSvcIgnored(Boolean(v))} />
                                <span>Ignoruj usługę</span>
                              </label>
                              <label className="flex items-center gap-1.5 cursor-pointer">
                                <Checkbox checked={svcFp} onCheckedChange={(v) => setSvcFp(Boolean(v))} />
                                <span>False Positive</span>
                              </label>
                            </div>
                            <div className="flex gap-2">
                              <Button
                                size="sm"
                                disabled={savingSvcOv}
                                onClick={() => handleSaveServiceOverride(svc.id)}
                              >
                                {savingSvcOv ? 'Zapis...' : 'Zapisz override usługi'}
                              </Button>
                              <Button size="sm" variant="outline" onClick={() => setEditingSvcId(null)}>
                                Anuluj
                              </Button>
                            </div>
                          </div>
                        )}

                        {svc.banner && (
                          <div className="text-xs font-mono text-muted-foreground">
                            Banner: <span className="text-foreground">{svc.banner}</span>
                          </div>
                        )}

                        {fp ? (
                          <div className="text-xs space-y-2.5 border-t border-border pt-3">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="font-mono text-foreground underline underline-offset-2">
                                {fp.url}
                              </span>
                              <Badge variant="secondary" className="font-mono">
                                HTTP {fp.status_code ?? '—'}
                              </Badge>
                              {typeof fp.response_time_ms === 'number' && (
                                <Badge
                                  variant={fp.response_time_ms >= 400 ? 'default' : 'outline'}
                                  className="font-mono text-[10px]"
                                >
                                  {fp.response_time_ms} ms{fp.response_time_ms >= 400 ? ' (WOLNA)' : ''}
                                </Badge>
                              )}
                              {fp.probe_error && (
                                <Badge variant="default" className="font-mono uppercase text-[10px]">
                                  BŁĄD HTTP: {fp.probe_error}
                                </Badge>
                              )}
                              {fp.is_admin_panel && (
                                <Badge variant="default" className="font-mono uppercase text-[10px]">
                                  ADMIN PANEL
                                </Badge>
                              )}
                              {fp.is_staging_env && (
                                <Badge variant="outline" className="font-mono uppercase text-[10px]">
                                  STAGING / DEV
                                </Badge>
                              )}
                            </div>

                            {fp.title && (
                              <div className="text-foreground">
                                <span className="text-muted-foreground">Tytuł:</span> {fp.title}
                              </div>
                            )}

                            {(fp.redirect_chain || []).length > 0 && (
                              <div className="text-foreground font-mono text-[11px]">
                                <span className="font-sans text-muted-foreground">
                                  Przekierowania ({fp.redirect_chain.length}):
                                </span>{' '}
                                {fp.redirect_chain.join(' → ')}
                              </div>
                            )}

                            {(fp.technologies || []).length > 0 && (
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-muted-foreground">Technologie (pewność):</span>
                                {(fp.technologies || []).map((t) => {
                                  const conf = fp.tech_confidence?.[t];
                                  return (
                                    <Badge key={t} variant="secondary" className="font-mono">
                                      {t}
                                      {conf ? ` (${conf})` : ''}
                                    </Badge>
                                  );
                                })}
                              </div>
                            )}

                            {fp.favicon_mmh3_hash && (
                              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-foreground">
                                <div>
                                  <span className="font-sans text-muted-foreground">Favicon MMH3:</span>{' '}
                                  {fp.favicon_mmh3_hash}
                                </div>
                                {canAdd && onCreateSignature && (
                                  <Button
                                    type="button"
                                    size="sm"
                                    variant="outline"
                                    className="h-6 px-2 text-[10px]"
                                    onClick={() => {
                                      const hash = fp.favicon_mmh3_hash || '';
                                      onClose();
                                      onCreateSignature({
                                        name: `Favicon ${selectedHost.hostname || selectedHost.ip_address} (${hash})`,
                                        description: `Wykrywa usługę po hashu Favicon MMH3 zaobserwowanym na ${selectedHost.ip_address}:${svc.port}`,
                                        severity: 'info',
                                        match_type: 'favicon_hash',
                                        favicon_hash: hash,
                                      });
                                    }}
                                  >
                                    <Plus className="h-3 w-3" />
                                    Sygnatura
                                  </Button>
                                )}
                              </div>
                            )}

                            {fp.tls_subject && (
                              <div className="p-2.5 rounded-md bg-muted border border-border font-mono text-[11px] space-y-1">
                                <div className="flex items-center justify-between gap-2">
                                  <span>TLS Subject: {fp.tls_subject}</span>
                                  {fp.tls_is_self_signed && (
                                    <Badge variant="outline" className="uppercase font-mono text-[10px]">
                                      SELF-SIGNED
                                    </Badge>
                                  )}
                                </div>
                                <div>TLS Issuer: {fp.tls_issuer}</div>
                                <div>Wygasa: {formatTime(fp.tls_not_after)}</div>
                                {(fp.tls_san || []).length > 0 && (
                                  <div>SAN: {fp.tls_san.join(', ')}</div>
                                )}
                              </div>
                            )}

                            <div>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() =>
                                  setExpandedHeaders((prev) => ({ ...prev, [svc.id]: !prev[svc.id] }))
                                }
                                className="h-7 px-2 text-[11px]"
                              >
                                {showHdr ? (
                                  <>
                                    <ChevronUp className="h-3 w-3" />
                                    Ukryj odszyfrowane nagłówki i ciasteczka HTTP
                                  </>
                                ) : (
                                  <>
                                    <ChevronDown className="h-3 w-3" />
                                    Pokaż odszyfrowane nagłówki ({Object.keys(fp.headers || {}).length}) i ciasteczka (
                                    {(fp.cookies || []).length})
                                  </>
                                )}
                              </Button>
                              {showHdr && (
                                <div className="mt-2 space-y-2.5 p-3 rounded-md bg-muted border border-border text-[11px]">
                                  {(fp.cookies || []).length > 0 && (
                                    <div className="space-y-1">
                                      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                        Ciasteczka ({fp.cookies.length})
                                      </div>
                                      <div className="flex flex-wrap gap-1.5">
                                        {fp.cookies.map((ck) => (
                                          <span
                                            key={ck}
                                            className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-0.5 font-mono text-foreground"
                                          >
                                            <span>{ck}</span>
                                            {canAdd && onCreateSignature && (
                                              <button
                                                type="button"
                                                title={`Utwórz sygnaturę z ciasteczka ${ck}`}
                                                onClick={() => {
                                                  onClose();
                                                  onCreateSignature({
                                                    name: `Cookie: ${ck}`,
                                                    description: `Wykrywa ciasteczko ${ck} zaobserwowane na ${selectedHost.ip_address}:${svc.port}`,
                                                    severity: 'info',
                                                    match_type: 'cookie',
                                                    cookie_name: ck,
                                                  });
                                                }}
                                                className="ml-0.5 text-muted-foreground hover:text-foreground"
                                              >
                                                <Plus className="h-3 w-3" />
                                              </button>
                                            )}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {Object.keys(fp.headers || {}).length > 0 && (
                                    <div className="space-y-1">
                                      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                                        Nagłówki HTTP ({Object.keys(fp.headers || {}).length})
                                      </div>
                                      <div className="divide-y divide-border/70 rounded border border-border bg-background">
                                        {Object.entries(fp.headers || {}).map(([hk, hv]) => (
                                          <div
                                            key={hk}
                                            className="flex items-center justify-between gap-2 px-2 py-1 font-mono"
                                          >
                                            <div className="min-w-0 break-all">
                                              <span className="font-semibold text-foreground">{hk}:</span>{' '}
                                              <span className="text-muted-foreground">{hv}</span>
                                            </div>
                                            {canAdd && onCreateSignature && (
                                              <Button
                                                type="button"
                                                size="sm"
                                                variant="ghost"
                                                className="h-6 px-1.5 text-[10px] shrink-0"
                                                title={`Utwórz sygnaturę z nagłówka ${hk}`}
                                                onClick={() => {
                                                  onClose();
                                                  onCreateSignature({
                                                    name: `Header: ${hk}`,
                                                    description: `Wykrywa nagłówek ${hk} zaobserwowany na ${selectedHost.ip_address}:${svc.port}`,
                                                    severity: 'info',
                                                    match_type: 'header',
                                                    header_name: hk,
                                                    header_value: hv,
                                                    header_op: 'contains',
                                                    sample_hint: `${hk}: ${hv}`,
                                                  });
                                                }}
                                              >
                                                <Plus className="h-3 w-3" />
                                                Sygnatura
                                              </Button>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  <details>
                                    <summary className="cursor-pointer font-mono text-[10px] text-muted-foreground hover:text-foreground">
                                      Surowy JSON nagłówków i ciasteczek
                                    </summary>
                                    <pre className="mt-1.5 p-2 rounded bg-background border border-border text-[10px] font-mono text-foreground overflow-x-auto">
                                      {JSON.stringify({ headers: fp.headers || {}, cookies: fp.cookies || [] }, null, 2)}
                                    </pre>
                                  </details>
                                </div>
                              )}
                            </div>
                          </div>
                        ) : (
                          <div className="text-[11px] text-muted-foreground border-t border-border pt-2">
                            Brak fingerprintu HTTP (usługa nie-webowa lub brak odpowiedzi HTTP).
                          </div>
                        )}

                        {svc.signature_matches.length > 0 && (
                          <div className="border-t border-border pt-3 space-y-1.5">
                            <div className="text-[11px] text-muted-foreground font-medium">
                              Dopasowane sygnatury ({svc.signature_matches.length}):
                            </div>
                            {svc.signature_matches.map((m) => (
                              <div
                                key={m.id}
                                className="flex flex-wrap items-center justify-between gap-2 p-2 rounded-md bg-muted/70 border border-border text-xs"
                              >
                                <div className="flex items-center gap-2">
                                  <SeverityBadge severity={m.severity} />
                                  <span className="font-medium text-foreground">{m.signature_name}</span>
                                </div>
                                <span className="font-mono text-[11px] text-muted-foreground">
                                  {m.matched_evidence}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              <Separator />

              {/* Formularz asset_overrides (poziom hosta) */}
              <Card>
                <CardContent className="p-4">
                  <form onSubmit={handleSaveOverride} className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground flex items-center gap-1.5">
                        <Lock className="h-3.5 w-3.5" />
                        Overrides Hosta (asset_overrides)
                      </h4>
                      {!canModify && (
                        <Badge variant="outline" className="font-mono">
                          Tylko odczyt ({role})
                        </Badge>
                      )}
                    </div>

                    {saveMessage && (
                      <Alert>
                        <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
                        <AlertDescription className="text-foreground">{saveMessage}</AlertDescription>
                      </Alert>
                    )}
                    {saveError && (
                      <Alert variant="destructive">
                        <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                        <AlertDescription className="text-foreground">{saveError}</AlertDescription>
                      </Alert>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Własna etykieta</span>
                        <Input
                          disabled={!canModify}
                          value={customLabel}
                          onChange={(e) => setCustomLabel(e.target.value)}
                        />
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Jednostka / właściciel (AGH)</span>
                        <Input
                          disabled={!canModify}
                          value={ownerUnit}
                          onChange={(e) => setOwnerUnit(e.target.value)}
                        />
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Krytyczność</span>
                        <Select
                          disabled={!canModify}
                          value={criticality}
                          onChange={(e) => setCriticality(e.target.value)}
                        >
                          <option value="">Brak</option>
                          <option value="info">info</option>
                          <option value="low">low</option>
                          <option value="medium">medium</option>
                          <option value="high">high</option>
                          <option value="critical">critical</option>
                        </Select>
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Tagi (oddzielone przecinkiem)</span>
                        <Input
                          disabled={!canModify}
                          value={tagsInput}
                          onChange={(e) => setTagsInput(e.target.value)}
                          placeholder="lab, web, prod"
                        />
                      </label>
                    </div>

                    <label className="block space-y-1 text-xs">
                      <span className="text-muted-foreground">
                        Notatka analityka (szyfrowana AES-256-GCM + AAD w bazie)
                      </span>
                      <Textarea
                        rows={3}
                        disabled={!canModify}
                        value={notes}
                        onChange={(e) => setNotes(e.target.value)}
                      />
                    </label>

                    <div className="flex flex-wrap items-center gap-5 pt-1 text-xs text-foreground">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <Checkbox
                          disabled={!canModify}
                          checked={isIgnored}
                          onCheckedChange={(v) => setIsIgnored(Boolean(v))}
                        />
                        <span>Ignoruj (pomijaj przy eksporcie do DefectDojo)</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <Checkbox
                          disabled={!canModify}
                          checked={isFalsePositive}
                          onCheckedChange={(v) => setIsFalsePositive(Boolean(v))}
                        />
                        <span>False Positive</span>
                      </label>
                    </div>

                    {canModify && (
                      <Button type="submit" disabled={savingOverride} className="mt-2">
                        {savingOverride ? 'Zapisywanie...' : 'Zapisz nadpisanie'}
                      </Button>
                    )}
                  </form>
                </CardContent>
              </Card>
            </div>
          )}
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
