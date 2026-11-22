import {
  AlertCircle,
  Check,
  CheckCircle2,
  Code2,
  Cookie,
  Copy,
  Database,
  Edit3,
  FileCode2,
  FileText,
  FlaskConical,
  Globe,
  Image as ImageIcon,
  Plus,
  Sparkles,
  Wand2,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { apiFetch } from '../../api';
import type {
  ObservedArtifactsResponse,
  Severity,
  SignatureDraft,
  SignatureItem,
  SignatureMatchType,
  SignatureTestResponse,
  UserRole,
} from '../../types';
import { Alert, AlertDescription } from '../ui/alert';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Checkbox } from '../ui/checkbox';
import { Input } from '../ui/input';
import { Select } from '../ui/select';
import { Textarea } from '../ui/textarea';
import {
  applyDraftToVisual,
  buildPatternFromVisual,
  COOKIE_SUGGESTIONS,
  getDefaultSampleForType,
  HEADER_SUGGESTIONS,
  type HeaderOperator,
  INITIAL_BUILDER_STATE,
  MATCH_TYPE_META,
  parseSignatureToVisual,
  PATH_SUGGESTIONS,
  SIGNATURE_PRESETS,
  type SignaturePreset,
  type VisualBuilderState,
} from './signatureBuilderUtils';

interface Props {
  role: UserRole;
  canAdd: boolean;
  canModify: boolean;
  editingSignature: SignatureItem | null;
  incomingDraft: SignatureDraft | null;
  artifacts: ObservedArtifactsResponse | null;
  onSaved: (message: string) => void;
  onCancelEdit: () => void;
  onClose?: () => void;
  onDraftApplied: () => void;
}

const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

const MATCH_TYPE_ICONS: Record<SignatureMatchType, typeof FileCode2> = {
  header: FileCode2,
  cookie: Cookie,
  favicon_hash: ImageIcon,
  html_fragment: Code2,
  footer_version: FileText,
  path_probe: Globe,
};

export function SignatureBuilderPanel({
  role,
  canAdd,
  canModify,
  editingSignature,
  incomingDraft,
  artifacts,
  onSaved,
  onCancelEdit,
  onClose,
  onDraftApplied,
}: Props) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<Severity>('low');
  const [matchType, setMatchType] = useState<SignatureMatchType>('header');
  const [visual, setVisual] = useState<VisualBuilderState>(INITIAL_BUILDER_STATE);
  const [advancedMode, setAdvancedMode] = useState(false);
  const [manualPattern, setManualPattern] = useState('');
  const [manualProbePath, setManualProbePath] = useState('/admin');
  const [manualExpectedStatus, setManualExpectedStatus] = useState('200');

  const [showJsonPreview, setShowJsonPreview] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Live Tester state
  const [showTester, setShowTester] = useState(false);
  const [sampleHeaders, setSampleHeaders] = useState(getDefaultSampleForType('header').headers);
  const [sampleCookies, setSampleCookies] = useState(getDefaultSampleForType('cookie').cookies);
  const [sampleHtml, setSampleHtml] = useState(getDefaultSampleForType('html_fragment').html);
  const [sampleStatus, setSampleStatus] = useState('200');
  const [sampleFavicon, setSampleFavicon] = useState(getDefaultSampleForType('favicon_hash').faviconHash);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<SignatureTestResponse | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  // Załaduj edytowaną sygnaturę do kreatora
  useEffect(() => {
    if (!editingSignature) return;
    setName(editingSignature.name);
    setDescription(editingSignature.description || '');
    setSeverity(editingSignature.severity);
    setMatchType(editingSignature.match_type);
    const { state, canUseVisual } = parseSignatureToVisual(editingSignature);
    setVisual(state);
    setAdvancedMode(!canUseVisual);
    setManualPattern(editingSignature.pattern);
    setManualProbePath(editingSignature.probe_path || '');
    setManualExpectedStatus(editingSignature.expected_status ? String(editingSignature.expected_status) : '');
    setError(null);
    setTestResult(null);
    setTestError(null);
  }, [editingSignature]);

  // Załaduj szkic z HostsTab ("+ Sygnatura" przy nagłówku / ciasteczku / faviconie)
  useEffect(() => {
    if (!incomingDraft) return;
    if (editingSignature) onCancelEdit();
    setName(incomingDraft.name || '');
    setDescription(incomingDraft.description || '');
    setSeverity(incomingDraft.severity || 'info');
    setMatchType(incomingDraft.match_type);
    const { state, useAdvanced } = applyDraftToVisual(incomingDraft);
    setVisual(state);
    setAdvancedMode(useAdvanced);
    if (useAdvanced && incomingDraft.pattern) {
      setManualPattern(incomingDraft.pattern);
    }
    if (incomingDraft.match_type === 'header' && incomingDraft.sample_hint) {
      setSampleHeaders(incomingDraft.sample_hint);
    } else if (incomingDraft.match_type === 'cookie' && incomingDraft.cookie_name) {
      setSampleCookies(incomingDraft.cookie_name);
    } else if (incomingDraft.match_type === 'favicon_hash' && incomingDraft.favicon_hash) {
      setSampleFavicon(incomingDraft.favicon_hash);
    }
    setError(null);
    setTestResult(null);
    setShowTester(true);
    onDraftApplied();
  }, [incomingDraft, editingSignature, onCancelEdit, onDraftApplied]);

  const effectivePattern = useMemo(
    () => (advancedMode ? manualPattern : buildPatternFromVisual(matchType, visual)),
    [advancedMode, manualPattern, matchType, visual]
  );

  const effectiveProbePath =
    matchType === 'path_probe' ? (advancedMode ? manualProbePath : visual.probePath).trim() || null : null;

  const effectiveExpectedStatus = useMemo(() => {
    if (matchType !== 'path_probe') return null;
    const raw = (advancedMode ? manualExpectedStatus : visual.expectedStatus).trim();
    if (!raw) return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  }, [matchType, advancedMode, manualExpectedStatus, visual.expectedStatus]);

  const singleJsonPreview = useMemo(() => {
    const obj = {
      name: name.trim() || 'Nazwa sygnatury',
      description: description.trim() || null,
      severity,
      match_type: matchType,
      pattern: effectivePattern,
      probe_path: effectiveProbePath,
      expected_status: effectiveExpectedStatus,
      is_enabled: editingSignature ? editingSignature.is_enabled : true,
    };
    return JSON.stringify(obj, null, 2);
  }, [name, description, severity, matchType, effectivePattern, effectiveProbePath, effectiveExpectedStatus, editingSignature]);

  const mergedHeaderSuggestions = useMemo(() => {
    const observed = artifacts?.header_names || [];
    return Array.from(new Set([...observed.slice(0, 8), ...HEADER_SUGGESTIONS])).slice(0, 12);
  }, [artifacts]);

  const mergedCookieSuggestions = useMemo(() => {
    const observed = artifacts?.cookies || [];
    return Array.from(new Set([...observed.slice(0, 8), ...COOKIE_SUGGESTIONS])).slice(0, 12);
  }, [artifacts]);

  function resetForm() {
    setName('');
    setDescription('');
    setSeverity('low');
    setMatchType('header');
    setVisual(INITIAL_BUILDER_STATE);
    setAdvancedMode(false);
    setManualPattern('');
    setManualProbePath('/admin');
    setManualExpectedStatus('200');
    setError(null);
    setTestResult(null);
    setTestError(null);
  }

  function handleSelectType(nextType: SignatureMatchType) {
    setMatchType(nextType);
    setTestResult(null);
    setTestError(null);
    const sample = getDefaultSampleForType(nextType);
    if (nextType === 'header' && !sampleHeaders) setSampleHeaders(sample.headers);
    if (nextType === 'cookie' && !sampleCookies) setSampleCookies(sample.cookies);
    if ((nextType === 'html_fragment' || nextType === 'footer_version' || nextType === 'path_probe')) {
      setSampleHtml(sample.html);
    }
    if (nextType === 'favicon_hash' && !sampleFavicon) {
      setSampleFavicon(artifacts?.favicons?.[0]?.hash || sample.faviconHash);
    }
    if (advancedMode) {
      setManualPattern(buildPatternFromVisual(nextType, visual));
    }
  }

  function applyPreset(preset: SignaturePreset) {
    if (editingSignature) onCancelEdit();
    setName(preset.name);
    setDescription(preset.description);
    setSeverity(preset.severity);
    setMatchType(preset.match_type);
    setVisual({ ...INITIAL_BUILDER_STATE, ...preset.state });
    setAdvancedMode(false);
    setError(null);
    setTestResult(null);
    const sample = getDefaultSampleForType(preset.match_type);
    setSampleHtml(sample.html);
  }

  function toggleAdvancedMode() {
    if (!advancedMode) {
      // Przejście wizualny -> ręczny regex: kopiujemy aktualnie wygenerowany wzorzec
      setManualPattern(buildPatternFromVisual(matchType, visual));
      setManualProbePath(visual.probePath);
      setManualExpectedStatus(visual.expectedStatus);
      setAdvancedMode(true);
    } else {
      // Powrót do kreatora wizualnego
      setAdvancedMode(false);
    }
    setTestResult(null);
  }

  async function handleCopySingleJson() {
    try {
      await navigator.clipboard.writeText(singleJsonPreview);
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 1800);
    } catch {
      // ignore clipboard errors
    }
  }

  async function handleRunTest(testAgainstDb: boolean) {
    setTesting(true);
    setTestError(null);
    setTestResult(null);
    try {
      const res = await apiFetch<SignatureTestResponse>('/signatures/test', role, {
        method: 'POST',
        body: JSON.stringify({
          match_type: matchType,
          pattern: effectivePattern,
          probe_path: effectiveProbePath,
          expected_status: effectiveExpectedStatus,
          sample_headers: matchType === 'header' ? sampleHeaders : null,
          sample_cookies: matchType === 'cookie' ? sampleCookies : null,
          sample_html:
            matchType === 'html_fragment' || matchType === 'footer_version' || matchType === 'path_probe'
              ? sampleHtml
              : null,
          sample_status_code: matchType === 'path_probe' && sampleStatus ? Number(sampleStatus) : null,
          sample_favicon_hash: matchType === 'favicon_hash' ? sampleFavicon : null,
          test_against_db: testAgainstDb,
        }),
      });
      setTestResult(res);
    } catch (err) {
      setTestError(err instanceof Error ? err.message : 'Błąd testowania sygnatury');
    } finally {
      setTesting(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError('Podaj nazwę sygnatury.');
      return;
    }
    if (matchType !== 'path_probe' && !effectivePattern.trim()) {
      setError('Wzorzec dopasowania nie może być pusty — uzupełnij pola warunku.');
      return;
    }
    if (editingSignature ? !canModify : !canAdd) return;

    setSubmitting(true);
    setError(null);
    try {
      const payload = {
        name: name.trim(),
        description: description.trim() || null,
        severity,
        match_type: matchType,
        pattern: effectivePattern,
        probe_path: effectiveProbePath,
        expected_status: effectiveExpectedStatus,
      };
      if (editingSignature) {
        await apiFetch(`/signatures/${editingSignature.id}`, role, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        });
        resetForm();
        onCancelEdit();
        onSaved(`Zaktualizowano sygnaturę: "${payload.name}".`);
      } else {
        await apiFetch('/signatures', role, {
          method: 'POST',
          body: JSON.stringify({ ...payload, is_enabled: true }),
        });
        resetForm();
        onSaved(`Dodano nową sygnaturę pasywną: "${payload.name}".`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu sygnatury');
    } finally {
      setSubmitting(false);
    }
  }

  const activeMeta = MATCH_TYPE_META.find((m) => m.type === matchType)!;
  const patternTooLong = effectivePattern.length > 256;

  return (
    <Card>
      <CardHeader className="pb-3 flex-row flex-wrap items-center justify-between gap-2 space-y-0 border-b border-border">
        <div className="flex items-center gap-2">
          <Wand2 className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm">
            {editingSignature ? `Edycja sygnatury: ${editingSignature.name}` : 'Kreator sygnatury (Wyklikiwacz)'}
          </CardTitle>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            type="button"
            size="sm"
            variant={advancedMode ? 'default' : 'outline'}
            onClick={toggleAdvancedMode}
            className="h-7 px-2.5 text-[11px] font-mono"
          >
            <Code2 className="h-3 w-3" />
            {advancedMode ? 'Tryb: Regex RE2' : 'Tryb: Wizualny'}
          </Button>
          {editingSignature ? (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                resetForm();
                onCancelEdit();
              }}
              className="h-7 px-2 text-xs"
            >
              <X className="h-3.5 w-3.5" />
              Anuluj edycję
            </Button>
          ) : (
            onClose && (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={onClose}
                className="h-7 px-2 text-xs"
                title="Zwiń kreator"
              >
                <X className="h-3.5 w-3.5" />
                Zwiń
              </Button>
            )
          )}
        </div>
      </CardHeader>

      <CardContent className="p-4 space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <AlertDescription className="text-foreground">{error}</AlertDescription>
          </Alert>
        )}

        {/* Szybkie szablony (1-klik) */}
        {!editingSignature && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <Sparkles className="h-3 w-3" />
              <span>Szybkie szablony (1-klik):</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {SIGNATURE_PRESETS.map((p) => (
                <Button
                  key={p.id}
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => applyPreset(p)}
                  className="h-7 px-2.5 text-[11px]"
                >
                  {p.label}
                </Button>
              ))}
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {/* Krok 1: Kafelki wyboru typu dopasowania */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              1. Co ma wykrywać sygnatura?
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              {MATCH_TYPE_META.map((item) => {
                const Icon = MATCH_TYPE_ICONS[item.type];
                const selected = matchType === item.type;
                return (
                  <button
                    key={item.type}
                    type="button"
                    onClick={() => handleSelectType(item.type)}
                    className={`text-left rounded-md border p-2.5 transition-colors ${
                      selected
                        ? 'border-primary bg-secondary text-foreground'
                        : 'border-border bg-background hover:bg-muted/60 text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-medium text-xs text-foreground">
                      <Icon className="h-3.5 w-3.5 shrink-0" />
                      <span className="truncate">{item.label}</span>
                    </div>
                    <div className="mt-1 text-[10px] leading-snug text-muted-foreground line-clamp-2">
                      {item.shortDesc}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Krok 2: Nazwa, Severity, Opis */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
            <label className="space-y-1 md:col-span-5">
              <span className="text-muted-foreground">Nazwa reguły *</span>
              <Input
                required
                maxLength={128}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="np. Exposed Staging Header (X-Environment)"
              />
            </label>
            <div className="space-y-1 md:col-span-4">
              <span className="text-muted-foreground block">Krytyczność (Severity)</span>
              <div className="flex items-center gap-1">
                {SEVERITIES.map((sev) => (
                  <Button
                    key={sev}
                    type="button"
                    size="sm"
                    variant={severity === sev ? 'default' : 'outline'}
                    onClick={() => setSeverity(sev)}
                    className="h-9 flex-1 px-1.5 text-[10px] font-mono uppercase"
                  >
                    {sev}
                  </Button>
                ))}
              </div>
            </div>
            <label className="space-y-1 md:col-span-3">
              <span className="text-muted-foreground">Opis (opcjonalnie)</span>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Krótki kontekst dla analityka"
              />
            </label>
          </div>

          {/* Krok 3: Warunek (Wyklikiwacz albo tryb zaawansowany RE2) */}
          <div className="rounded-md border border-border bg-muted/30 p-3.5 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-[11px] font-medium uppercase tracking-wider text-foreground">
                2. Warunek dopasowania — {activeMeta.label}
              </div>
              <span className="text-[11px] text-muted-foreground">{activeMeta.passiveHint}</span>
            </div>

            {!advancedMode ? (
              <>
                {matchType === 'header' && (
                  <div className="space-y-2.5">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Nazwa nagłówka HTTP *</span>
                        <Input
                          value={visual.headerName}
                          onChange={(e) => setVisual((v) => ({ ...v, headerName: e.target.value }))}
                          placeholder="np. X-Powered-By"
                          className="font-mono"
                        />
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Operator</span>
                        <Select
                          value={visual.headerOp}
                          onChange={(e) =>
                            setVisual((v) => ({ ...v, headerOp: e.target.value as HeaderOperator }))
                          }
                        >
                          <option value="exists">Istnieje (dowolna wartość)</option>
                          <option value="contains">Wartość zawiera tekst</option>
                          <option value="starts_with">Wartość zaczyna się od</option>
                          <option value="equals">Wartość dokładnie równa</option>
                          <option value="version">Ujawnia numer wersji (np. /1.2)</option>
                        </Select>
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">
                          {visual.headerOp === 'exists'
                            ? 'Wartość (nie wymagana)'
                            : visual.headerOp === 'version'
                            ? 'Opcjonalna nazwa serwera (np. nginx)'
                            : 'Szukana wartość'}
                        </span>
                        <Input
                          disabled={visual.headerOp === 'exists'}
                          value={visual.headerValue}
                          onChange={(e) => setVisual((v) => ({ ...v, headerValue: e.target.value }))}
                          placeholder={visual.headerOp === 'version' ? 'opcjonalnie np. nginx, PHP' : 'np. PHP/7.4'}
                          className="font-mono"
                        />
                      </label>
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-1">
                        <span className="text-[10px] text-muted-foreground mr-1">Popularne / z bazy:</span>
                        {mergedHeaderSuggestions.map((hdr) => (
                          <button
                            key={hdr}
                            type="button"
                            onClick={() => setVisual((v) => ({ ...v, headerName: hdr }))}
                            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                              visual.headerName.toLowerCase() === hdr.toLowerCase()
                                ? 'border-primary bg-primary text-primary-foreground'
                                : 'border-border bg-background text-muted-foreground hover:text-foreground'
                            }`}
                          >
                            {hdr}
                          </button>
                        ))}
                      </div>
                      <label className="flex items-center gap-1.5 cursor-pointer text-foreground">
                        <Checkbox
                          checked={visual.caseInsensitive}
                          onCheckedChange={(c) => setVisual((v) => ({ ...v, caseInsensitive: Boolean(c) }))}
                        />
                        <span>Ignoruj wielkość liter</span>
                      </label>
                    </div>
                  </div>
                )}

                {matchType === 'cookie' && (
                  <div className="space-y-2.5">
                    <label className="block space-y-1 max-w-md">
                      <span className="text-muted-foreground">Nazwa (lub fragment nazwy) ciasteczka *</span>
                      <Input
                        value={visual.cookieName}
                        onChange={(e) => setVisual((v) => ({ ...v, cookieName: e.target.value }))}
                        placeholder="np. PHPSESSID, grafana_session"
                        className="font-mono"
                      />
                    </label>
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-[10px] text-muted-foreground mr-1">Popularne / z bazy:</span>
                      {mergedCookieSuggestions.map((ck) => (
                        <button
                          key={ck}
                          type="button"
                          onClick={() => setVisual((v) => ({ ...v, cookieName: ck }))}
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                            visual.cookieName.toLowerCase() === ck.toLowerCase()
                              ? 'border-primary bg-primary text-primary-foreground'
                              : 'border-border bg-background text-muted-foreground hover:text-foreground'
                          }`}
                        >
                          {ck}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {matchType === 'favicon_hash' && (
                  <div className="space-y-2.5">
                    <label className="block space-y-1 max-w-md">
                      <span className="text-muted-foreground">Hash Favicon MMH3 (liczba ze znakiem, standard Shodan) *</span>
                      <Input
                        value={visual.faviconHash}
                        onChange={(e) => setVisual((v) => ({ ...v, faviconHash: e.target.value }))}
                        placeholder="np. -1986957532"
                        className="font-mono"
                      />
                    </label>
                    {artifacts && artifacts.favicons.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-[10px] text-muted-foreground block">
                          Wykryte favicony w Twojej bazie (kliknij, aby wybrać):
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {artifacts.favicons.map((fav) => (
                            <button
                              key={fav.hash}
                              type="button"
                              onClick={() => {
                                setVisual((v) => ({ ...v, faviconHash: fav.hash }));
                                setSampleFavicon(fav.hash);
                              }}
                              className={`rounded border px-2 py-1 font-mono text-[10px] transition-colors ${
                                visual.faviconHash === fav.hash
                                  ? 'border-primary bg-primary text-primary-foreground'
                                  : 'border-border bg-background text-muted-foreground hover:text-foreground'
                              }`}
                            >
                              {fav.hash} ({fav.sample_endpoints.slice(0, 2).join(', ')})
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {matchType === 'html_fragment' && (
                  <div className="space-y-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        type="button"
                        size="sm"
                        variant={visual.htmlMode === 'phrases' ? 'default' : 'outline'}
                        onClick={() => setVisual((v) => ({ ...v, htmlMode: 'phrases' }))}
                        className="h-7 px-2.5 text-[11px]"
                      >
                        Proste frazy (dowolna z listy)
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant={visual.htmlMode === 'meta_generator' ? 'default' : 'outline'}
                        onClick={() => setVisual((v) => ({ ...v, htmlMode: 'meta_generator' }))}
                        className="h-7 px-2.5 text-[11px]"
                      >
                        Tag &lt;meta name=&quot;generator&quot;&gt; (CMS)
                      </Button>
                      <label className="flex items-center gap-1.5 cursor-pointer text-foreground ml-auto">
                        <Checkbox
                          checked={visual.caseInsensitive}
                          onCheckedChange={(c) => setVisual((v) => ({ ...v, caseInsensitive: Boolean(c) }))}
                        />
                        <span>Ignoruj wielkość liter</span>
                      </label>
                    </div>
                    {visual.htmlMode === 'phrases' ? (
                      <label className="block space-y-1">
                        <span className="text-muted-foreground">
                          Frazy w kodzie HTML (oddzielone przecinkiem lub nową linią — znaki specjalne są automatycznie escapowane)
                        </span>
                        <Input
                          value={visual.htmlPhrases}
                          onChange={(e) => setVisual((v) => ({ ...v, htmlPhrases: e.target.value }))}
                          placeholder="np. phpmyadmin, adminer.org, wp-content/"
                          className="font-mono"
                        />
                      </label>
                    ) : (
                      <label className="block space-y-1 max-w-md">
                        <span className="text-muted-foreground">
                          Nazwa CMS w meta generator (zostaw puste, aby wykrywać dowolny CMS z numerem wersji)
                        </span>
                        <Input
                          value={visual.htmlMetaCms}
                          onChange={(e) => setVisual((v) => ({ ...v, htmlMetaCms: e.target.value }))}
                          placeholder="np. WordPress, Drupal, Joomla (lub puste)"
                          className="font-mono"
                        />
                      </label>
                    )}
                  </div>
                )}

                {matchType === 'footer_version' && (
                  <div className="space-y-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        type="button"
                        size="sm"
                        variant={visual.footerMode === 'app_version' ? 'default' : 'outline'}
                        onClick={() => setVisual((v) => ({ ...v, footerMode: 'app_version' }))}
                        className="h-7 px-2.5 text-[11px]"
                      >
                        Aplikacja + numer wersji (x.y)
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant={visual.footerMode === 'phrases' ? 'default' : 'outline'}
                        onClick={() => setVisual((v) => ({ ...v, footerMode: 'phrases' }))}
                        className="h-7 px-2.5 text-[11px]"
                      >
                        Proste frazy w stopce
                      </Button>
                      <label className="flex items-center gap-1.5 cursor-pointer text-foreground ml-auto">
                        <Checkbox
                          checked={visual.caseInsensitive}
                          onCheckedChange={(c) => setVisual((v) => ({ ...v, caseInsensitive: Boolean(c) }))}
                        />
                        <span>Ignoruj wielkość liter</span>
                      </label>
                    </div>
                    {visual.footerMode === 'app_version' ? (
                      <label className="block space-y-1 max-w-md">
                        <span className="text-muted-foreground">
                          Nazwa aplikacji/CMS (zostaw puste, aby wykrywać ogólne &quot;Powered by ... vX.Y&quot;)
                        </span>
                        <Input
                          value={visual.footerApp}
                          onChange={(e) => setVisual((v) => ({ ...v, footerApp: e.target.value }))}
                          placeholder="np. LegacyCMS, Moodle, Gitea (lub puste)"
                          className="font-mono"
                        />
                      </label>
                    ) : (
                      <label className="block space-y-1">
                        <span className="text-muted-foreground">Frazy szukane w &lt;footer&gt; (po przecinku)</span>
                        <Input
                          value={visual.footerPhrases}
                          onChange={(e) => setVisual((v) => ({ ...v, footerPhrases: e.target.value }))}
                          placeholder="np. Powered by, Build version"
                          className="font-mono"
                        />
                      </label>
                    )}
                  </div>
                )}

                {matchType === 'path_probe' && (
                  <div className="space-y-2.5">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Ścieżka względna GET *</span>
                        <Input
                          required
                          value={visual.probePath}
                          onChange={(e) => setVisual((v) => ({ ...v, probePath: e.target.value }))}
                          placeholder="/admin"
                          className="font-mono"
                        />
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Oczekiwany kod HTTP</span>
                        <Select
                          value={visual.expectedStatus}
                          onChange={(e) => setVisual((v) => ({ ...v, expectedStatus: e.target.value }))}
                          className="font-mono"
                        >
                          <option value="200">200 (OK)</option>
                          <option value="">Dowolny 2xx / 3xx</option>
                          <option value="301">301 (Moved Permanently)</option>
                          <option value="302">302 (Found / Redirect)</option>
                          <option value="401">401 (Unauthorized — chroniony zasób)</option>
                          <option value="403">403 (Forbidden — istnieje, zablokowany)</option>
                        </Select>
                      </label>
                      <label className="space-y-1">
                        <span className="text-muted-foreground">Weryfikacja treści odpowiedzi</span>
                        <Select
                          value={visual.pathBodyMode}
                          onChange={(e) =>
                            setVisual((v) => ({
                              ...v,
                              pathBodyMode: e.target.value as 'any' | 'phrases',
                            }))
                          }
                        >
                          <option value="phrases">Treść zawiera jedną z fraz</option>
                          <option value="any">Dowolna treść (tylko status + anty-soft-404)</option>
                        </Select>
                      </label>
                    </div>
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-[10px] text-muted-foreground mr-1">Popularne ścieżki:</span>
                      {PATH_SUGGESTIONS.map((p) => (
                        <button
                          key={p}
                          type="button"
                          onClick={() => setVisual((v) => ({ ...v, probePath: p }))}
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                            visual.probePath === p
                              ? 'border-primary bg-primary text-primary-foreground'
                              : 'border-border bg-background text-muted-foreground hover:text-foreground'
                          }`}
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                    {visual.pathBodyMode === 'phrases' && (
                      <div className="flex flex-wrap items-end gap-3">
                        <label className="space-y-1 flex-1 min-w-[240px]">
                          <span className="text-muted-foreground">
                            Frazy w treści odpowiedzi (oddzielone przecinkiem — dopasowanie LUB)
                          </span>
                          <Input
                            value={visual.pathPhrases}
                            onChange={(e) => setVisual((v) => ({ ...v, pathPhrases: e.target.value }))}
                            placeholder="np. admin, dashboard, login, password"
                            className="font-mono"
                          />
                        </label>
                        <label className="flex items-center gap-1.5 cursor-pointer text-foreground pb-2">
                          <Checkbox
                            checked={visual.caseInsensitive}
                            onCheckedChange={(c) => setVisual((v) => ({ ...v, caseInsensitive: Boolean(c) }))}
                          />
                          <span>Ignoruj wielkość liter</span>
                        </label>
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              /* Tryb zaawansowany — ręczna edycja wzorca RE2 */
              <div className="space-y-3">
                <label className="block space-y-1">
                  <span className="text-muted-foreground">
                    {matchType === 'path_probe'
                      ? 'Wzorzec RE2 w treści odpowiedzi (opcjonalnie dla path_probe)'
                      : 'Wzorzec (RE2 regex / nazwa ciasteczka / hash MMH3) *'}
                  </span>
                  <Input
                    required={matchType !== 'path_probe'}
                    value={manualPattern}
                    onChange={(e) => setManualPattern(e.target.value)}
                    placeholder="(?i)^X-Powered-By:\s*.+"
                    className="font-mono"
                  />
                </label>
                {matchType === 'path_probe' && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <label className="space-y-1">
                      <span className="text-muted-foreground">Ścieżka względna (probe_path) *</span>
                      <Input
                        required
                        value={manualProbePath}
                        onChange={(e) => setManualProbePath(e.target.value)}
                        placeholder="/admin"
                        className="font-mono"
                      />
                    </label>
                    <label className="space-y-1">
                      <span className="text-muted-foreground">Oczekiwany kod HTTP (opcjonalnie)</span>
                      <Input
                        type="number"
                        min={100}
                        max={599}
                        value={manualExpectedStatus}
                        onChange={(e) => setManualExpectedStatus(e.target.value)}
                        placeholder="200"
                        className="font-mono"
                      />
                    </label>
                  </div>
                )}
              </div>
            )}

            {/* Pasek podglądu wygenerowanego wzorca RE2 */}
            <div className="pt-2 border-t border-border/70 flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2 min-w-0">
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground shrink-0">
                  Wynikowy wzorzec:
                </span>
                <code className="px-2 py-0.5 rounded bg-background border border-border font-mono text-[11px] text-foreground break-all">
                  {effectivePattern || (matchType === 'path_probe' ? '(dowolna treść — sam kod HTTP + anty-soft-404)' : '—')}
                </code>
                <span
                  className={`font-mono text-[10px] ${
                    patternTooLong ? 'text-foreground font-bold underline' : 'text-muted-foreground'
                  }`}
                >
                  {effectivePattern.length}/256
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowJsonPreview((v) => !v)}
                  className="h-7 px-2 text-[11px] font-mono"
                >
                  <Code2 className="h-3 w-3" />
                  {showJsonPreview ? 'Ukryj JSON' : 'Podgląd JSON'}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant={showTester ? 'secondary' : 'outline'}
                  onClick={() => setShowTester((v) => !v)}
                  className="h-7 px-2.5 text-[11px]"
                >
                  <FlaskConical className="h-3 w-3" />
                  Przetestuj regułę
                </Button>
              </div>
            </div>

            {showJsonPreview && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-muted-foreground">
                    Przenośna reprezentacja JSON tej sygnatury:
                  </span>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={handleCopySingleJson}
                    className="h-6 px-2 text-[10px]"
                  >
                    {copiedJson ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    {copiedJson ? 'Skopiowano' : 'Kopiuj JSON'}
                  </Button>
                </div>
                <pre className="p-2.5 rounded bg-background border border-border font-mono text-[11px] overflow-x-auto">
                  {singleJsonPreview}
                </pre>
              </div>
            )}
          </div>

          {/* Live Tester (próbka + test wsteczny na zebranych danych z bazy) */}
          {showTester && (
            <div className="rounded-md border border-border bg-card p-3.5 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 font-medium text-foreground">
                  <FlaskConical className="h-3.5 w-3.5" />
                  <span>Live Tester sygnatury (pasywny, zero ruchu sieciowego)</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={testing}
                    onClick={() => handleRunTest(false)}
                    className="h-7 px-2.5 text-[11px]"
                  >
                    {testing ? 'Testowanie...' : 'Testuj na próbce'}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    disabled={testing}
                    onClick={() => handleRunTest(true)}
                    className="h-7 px-2.5 text-[11px]"
                  >
                    <Database className="h-3 w-3" />
                    {testing ? 'Sprawdzanie...' : 'Sprawdź na hostach w bazie'}
                  </Button>
                </div>
              </div>

              {matchType === 'header' && (
                <label className="block space-y-1">
                  <span className="text-[11px] text-muted-foreground">Przykładowe nagłówki HTTP (po jednym w linii):</span>
                  <Textarea
                    rows={3}
                    value={sampleHeaders}
                    onChange={(e) => setSampleHeaders(e.target.value)}
                    className="font-mono text-[11px]"
                  />
                </label>
              )}
              {matchType === 'cookie' && (
                <label className="block space-y-1">
                  <span className="text-[11px] text-muted-foreground">Przykładowe nazwy ciasteczek (po przecinku):</span>
                  <Input
                    value={sampleCookies}
                    onChange={(e) => setSampleCookies(e.target.value)}
                    className="font-mono text-[11px]"
                  />
                </label>
              )}
              {matchType === 'favicon_hash' && (
                <label className="block space-y-1 max-w-md">
                  <span className="text-[11px] text-muted-foreground">Przykładowy hash Favicon MMH3:</span>
                  <Input
                    value={sampleFavicon}
                    onChange={(e) => setSampleFavicon(e.target.value)}
                    className="font-mono text-[11px]"
                  />
                </label>
              )}
              {(matchType === 'html_fragment' || matchType === 'footer_version' || matchType === 'path_probe') && (
                <div className="space-y-2">
                  {matchType === 'path_probe' && (
                    <label className="block space-y-1 max-w-[180px]">
                      <span className="text-[11px] text-muted-foreground">Kod HTTP próbki:</span>
                      <Input
                        type="number"
                        value={sampleStatus}
                        onChange={(e) => setSampleStatus(e.target.value)}
                        className="font-mono h-8 text-[11px]"
                      />
                    </label>
                  )}
                  <label className="block space-y-1">
                    <span className="text-[11px] text-muted-foreground">Przykładowa treść HTML odpowiedzi:</span>
                    <Textarea
                      rows={3}
                      value={sampleHtml}
                      onChange={(e) => setSampleHtml(e.target.value)}
                      className="font-mono text-[11px]"
                    />
                  </label>
                </div>
              )}

              {testError && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                  <AlertDescription className="text-foreground">{testError}</AlertDescription>
                </Alert>
              )}

              {testResult && (
                <div className="space-y-2.5 pt-1 border-t border-border">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge variant={testResult.sample_match ? 'default' : 'outline'} className="font-mono">
                      {testResult.sample_match ? 'PRÓBKA: DOPASOWANO' : 'PRÓBKA: BRAK DOPASOWANIA'}
                    </Badge>
                    {testResult.sample_evidence && (
                      <code className="font-mono text-[11px] text-foreground bg-muted px-2 py-0.5 rounded border border-border">
                        {testResult.sample_evidence}
                      </code>
                    )}
                    {testResult.sample_note && (
                      <span className="text-[11px] text-muted-foreground">{testResult.sample_note}</span>
                    )}
                  </div>

                  {testResult.db_test && (
                    <div className="rounded bg-muted/40 border border-border p-2.5 space-y-1.5">
                      {testResult.db_test.supported ? (
                        <>
                          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
                            <span>
                              Test na zebranych danych z bazy: sprawdzono{' '}
                              <strong>{testResult.db_test.services_checked}</strong> usług HTTP/HTTPS
                            </span>
                            <Badge
                              variant={testResult.db_test.matches_count > 0 ? 'default' : 'outline'}
                              className="font-mono text-[10px]"
                            >
                              Trafienia w bazie: {testResult.db_test.matches_count}
                            </Badge>
                          </div>
                          {testResult.db_test.matches.length > 0 && (
                            <div className="space-y-1 max-h-36 overflow-y-auto pt-1">
                              {testResult.db_test.matches.map((m, idx) => (
                                <div
                                  key={`${m.host_id}-${m.port}-${idx}`}
                                  className="flex flex-wrap items-center justify-between gap-2 px-2 py-1 rounded bg-background border border-border font-mono text-[11px]"
                                >
                                  <span className="font-semibold text-foreground">
                                    {m.ip_address}:{m.port}
                                    {m.hostname ? ` (${m.hostname})` : ''}
                                  </span>
                                  <span className="text-muted-foreground truncate max-w-md">{m.evidence}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="text-[11px] text-muted-foreground">{testResult.db_test.note}</div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Przycisk zapisu */}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div className="flex items-center gap-2">
              <Button type="submit" disabled={submitting || patternTooLong}>
                {editingSignature ? <Edit3 className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
                {submitting
                  ? 'Zapisywanie...'
                  : editingSignature
                  ? 'Zapisz zmiany sygnatury'
                  : 'Dodaj sygnaturę'}
              </Button>
              {!editingSignature && (
                <Button type="button" variant="ghost" size="sm" onClick={resetForm}>
                  Wyczyść pola
                </Button>
              )}
            </div>
            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Walidacja RE2 + ochrona ReDoS + wyłącznie pasywne sondy GET</span>
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
