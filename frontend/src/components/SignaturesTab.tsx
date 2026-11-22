import {
  AlertCircle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  Edit3,
  FileJson,
  Search,
  Trash2,
  Wand2,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type {
  ObservedArtifactsResponse,
  Severity,
  SignatureDraft,
  SignatureExportBundle,
  SignatureItem,
  SignatureMatchType,
  UserRole,
} from '../types';
import { SeverityBadge } from './Badges';
import { SignatureBuilderPanel } from './signatures/SignatureBuilderPanel';
import { SignatureJsonImportPanel } from './signatures/SignatureJsonImportPanel';
import { toPortableSignature } from './signatures/signatureBuilderUtils';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent } from './ui/card';
import { Checkbox, Switch } from './ui/checkbox';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
  initialDraft?: SignatureDraft | null;
  onDraftConsumed?: () => void;
}

type EditorMode = 'closed' | 'builder' | 'json';

export function SignaturesTab({ role, initialDraft = null, onDraftConsumed }: Props) {
  const [items, setItems] = useState<SignatureItem[]>([]);
  const [artifacts, setArtifacts] = useState<ObservedArtifactsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [editorMode, setEditorMode] = useState<EditorMode>('closed');
  const [editingSignature, setEditingSignature] = useState<SignatureItem | null>(null);
  const [activeDraft, setActiveDraft] = useState<SignatureDraft | null>(null);

  // Filtry i zaznaczanie tabeli (do eksportu)
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | SignatureMatchType>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'enabled' | 'disabled'>('all');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const [exporting, setExporting] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedBundle, setCopiedBundle] = useState(false);

  const canAdd = hasPermission(role, 'add');
  const canModify = hasPermission(role, 'modify');
  const canDelete = hasPermission(role, 'delete');

  async function loadSignatures() {
    try {
      const data = await apiFetch<SignatureItem[]>('/signatures', role);
      setItems(data);
      setSelectedIds((prev) => prev.filter((id) => data.some((s) => s.id === id)));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania sygnatur');
    }
  }

  async function loadArtifacts() {
    try {
      const data = await apiFetch<ObservedArtifactsResponse>('/signatures/observed-artifacts', role);
      setArtifacts(data);
    } catch {
      // opcjonalne podpowiedzi — ignoruj błędy w tle
    }
  }

  useEffect(() => {
    loadSignatures();
    loadArtifacts();
  }, [role]);

  // Obsługa przejścia z HostsTab ("+ Sygnatura")
  useEffect(() => {
    if (!initialDraft) return;
    setEditingSignature(null);
    setEditorMode('builder');
    setActiveDraft(initialDraft);
    setNotice('Wypełniono kreator na podstawie artefaktu wybranego z hosta — możesz od razu przetestować i zapisać regułę.');
    onDraftConsumed?.();
  }, [initialDraft, onDraftConsumed]);

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((sig) => {
      if (typeFilter !== 'all' && sig.match_type !== typeFilter) return false;
      if (severityFilter !== 'all' && sig.severity !== severityFilter) return false;
      if (statusFilter === 'enabled' && !sig.is_enabled) return false;
      if (statusFilter === 'disabled' && sig.is_enabled) return false;
      if (!q) return true;
      return (
        sig.name.toLowerCase().includes(q) ||
        (sig.description || '').toLowerCase().includes(q) ||
        sig.pattern.toLowerCase().includes(q) ||
        (sig.probe_path || '').toLowerCase().includes(q)
      );
    });
  }, [items, search, typeFilter, severityFilter, statusFilter]);

  const allFilteredSelected =
    filteredItems.length > 0 && filteredItems.every((s) => selectedIds.includes(s.id));

  function toggleSelectAllFiltered(checked: boolean) {
    if (checked) {
      setSelectedIds((prev) => Array.from(new Set([...prev, ...filteredItems.map((s) => s.id)])));
    } else {
      const visibleSet = new Set(filteredItems.map((s) => s.id));
      setSelectedIds((prev) => prev.filter((id) => !visibleSet.has(id)));
    }
  }

  function toggleSelectOne(id: string, checked: boolean) {
    setSelectedIds((prev) =>
      checked ? (prev.includes(id) ? prev : [...prev, id]) : prev.filter((x) => x !== id)
    );
  }

  async function handleToggle(sig: SignatureItem) {
    if (!canModify) return;
    setError(null);
    setNotice(null);
    setBusyId(sig.id);
    try {
      await apiFetch(`/signatures/${sig.id}`, role, {
        method: 'PATCH',
        body: JSON.stringify({ is_enabled: !sig.is_enabled }),
      });
      setNotice(`Zmieniono status sygnatury "${sig.name}" na ${!sig.is_enabled ? 'aktywna' : 'wyłączona'}.`);
      await loadSignatures();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zmiany statusu sygnatury');
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(sig: SignatureItem) {
    if (!canDelete) return;
    setError(null);
    setNotice(null);
    setBusyId(sig.id);
    try {
      await apiFetch(`/signatures/${sig.id}`, role, { method: 'DELETE' });
      if (editingSignature?.id === sig.id) {
        setEditingSignature(null);
        setEditorMode('closed');
      }
      setNotice(`Usunięto sygnaturę "${sig.name}".`);
      await loadSignatures();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania sygnatury');
    } finally {
      setBusyId(null);
    }
  }

  async function fetchExportBundle(onlyEnabled: boolean): Promise<SignatureExportBundle> {
    const params = new URLSearchParams();
    if (onlyEnabled) {
      params.set('only_enabled', 'true');
    } else if (selectedIds.length > 0) {
      params.set('ids', selectedIds.join(','));
    }
    const qs = params.toString();
    return apiFetch<SignatureExportBundle>(`/signatures/export${qs ? `?${qs}` : ''}`, role);
  }

  async function handleDownloadExport(onlyEnabled = false) {
    setExporting(true);
    setError(null);
    setNotice(null);
    try {
      const bundle = await fetchExportBundle(onlyEnabled);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = onlyEnabled ? 'janus_asi_signatures_active.json' : 'janus_asi_signatures.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setNotice(`Wyeksportowano ${bundle.count} sygnatur do pliku JSON.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd eksportu sygnatur');
    } finally {
      setExporting(false);
    }
  }

  async function handleCopyBundle(onlyEnabled = false) {
    setExporting(true);
    setError(null);
    setNotice(null);
    try {
      const bundle = await fetchExportBundle(onlyEnabled);
      await navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
      setCopiedBundle(true);
      setTimeout(() => setCopiedBundle(false), 1800);
      setNotice(`Skopiowano JSON z ${bundle.count} sygnaturami do schowka.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Nie udało się skopiować JSON do schowka');
    } finally {
      setExporting(false);
    }
  }

  async function handleCopySingle(sig: SignatureItem) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(toPortableSignature(sig), null, 2));
      setCopiedId(sig.id);
      setTimeout(() => setCopiedId(null), 1500);
    } catch {
      // ignore clipboard errors
    }
  }

  function handleStartEdit(sig: SignatureItem) {
    setEditingSignature(sig);
    setEditorMode('builder');
    setError(null);
    setNotice(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  const showEditorSection = Boolean(editingSignature ? canModify : canAdd);
  const enabledCount = items.filter((i) => i.is_enabled).length;

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

      {/* Górna sekcja: Kompaktowy pasek z rozwijanym kreatorem lub importem JSON */}
      {showEditorSection && (
        <div className="space-y-3">
          {!editingSignature && canAdd && (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant={editorMode === 'builder' ? 'default' : 'outline'}
                  onClick={() => setEditorMode((prev) => (prev === 'builder' ? 'closed' : 'builder'))}
                  className="h-8 px-3 text-xs"
                >
                  <Wand2 className="h-3.5 w-3.5" />
                  Kreator sygnatury
                  {editorMode === 'builder' ? (
                    <ChevronUp className="h-3.5 w-3.5 ml-0.5" />
                  ) : (
                    <ChevronDown className="h-3.5 w-3.5 ml-0.5" />
                  )}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant={editorMode === 'json' ? 'default' : 'outline'}
                  onClick={() => setEditorMode((prev) => (prev === 'json' ? 'closed' : 'json'))}
                  className="h-8 px-3 text-xs"
                >
                  <FileJson className="h-3.5 w-3.5" />
                  Import JSON (Wklej / Plik)
                  {editorMode === 'json' ? (
                    <ChevronUp className="h-3.5 w-3.5 ml-0.5" />
                  ) : (
                    <ChevronDown className="h-3.5 w-3.5 ml-0.5" />
                  )}
                </Button>
              </div>
              <span className="text-[11px] font-mono text-muted-foreground">
                Łącznie: {items.length} reguł ({enabledCount} aktywnych)
              </span>
            </div>
          )}

          {(editorMode === 'builder' || editingSignature) && (
            <SignatureBuilderPanel
              role={role}
              canAdd={canAdd}
              canModify={canModify}
              editingSignature={editingSignature}
              incomingDraft={activeDraft}
              artifacts={artifacts}
              onDraftApplied={() => setActiveDraft(null)}
              onCancelEdit={() => {
                setEditingSignature(null);
                setEditorMode('closed');
              }}
              onClose={() => setEditorMode('closed')}
              onSaved={async (msg) => {
                setNotice(msg);
                setError(null);
                setEditingSignature(null);
                setEditorMode('closed');
                await loadSignatures();
              }}
            />
          )}

          {editorMode === 'json' && !editingSignature && (
            <SignatureJsonImportPanel
              role={role}
              canModify={canModify}
              onClose={() => setEditorMode('closed')}
              onImported={async (msg) => {
                setNotice(msg);
                setError(null);
                await loadSignatures();
              }}
            />
          )}
        </div>
      )}

      {/* Pasek filtrów i eksportu JSON (dostępny dla każdej roli od read_only wzwyż) */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[240px]">
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Szukaj po nazwie, wzorcu, ścieżce..."
              className="pl-8 h-8 text-xs"
            />
          </div>
          <div className="w-36">
            <Select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value as 'all' | SignatureMatchType)}
              className="h-8 text-xs font-mono"
              aria-label="Filtr typu sygnatury"
            >
              <option value="all">Wszystkie typy</option>
              <option value="header">header</option>
              <option value="cookie">cookie</option>
              <option value="favicon_hash">favicon_hash</option>
              <option value="html_fragment">html_fragment</option>
              <option value="footer_version">footer_version</option>
              <option value="path_probe">path_probe</option>
            </Select>
          </div>
          <div className="w-32">
            <Select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as 'all' | Severity)}
              className="h-8 text-xs font-mono"
              aria-label="Filtr severity"
            >
              <option value="all">Każde severity</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </Select>
          </div>
          <div className="w-28">
            <Select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'enabled' | 'disabled')}
              className="h-8 text-xs font-mono"
              aria-label="Filtr statusu"
            >
              <option value="all">Status: All</option>
              <option value="enabled">Aktywne</option>
              <option value="disabled">Wyłączone</option>
            </Select>
          </div>
          <span className="text-[11px] font-mono text-muted-foreground">
            {filteredItems.length}/{items.length}
          </span>
        </div>

        {/* Przyciski eksportu JSON */}
        <div className="flex flex-wrap items-center gap-1.5">
          {selectedIds.length > 0 && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => setSelectedIds([])}
              className="h-8 px-2 text-[11px]"
            >
              Odznacz ({selectedIds.length})
            </Button>
          )}
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={exporting || items.length === 0}
            onClick={() => handleCopyBundle(false)}
            className="h-8 px-2.5 text-xs"
            title="Skopiuj JSON zaznaczonych (lub wszystkich) sygnatur do schowka"
          >
            {copiedBundle ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedBundle
              ? 'Skopiowano'
              : selectedIds.length > 0
              ? `Kopiuj JSON (${selectedIds.length})`
              : 'Kopiuj JSON'}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={exporting || items.length === 0}
            onClick={() => handleDownloadExport(false)}
            className="h-8 px-2.5 text-xs"
          >
            <Download className="h-3.5 w-3.5" />
            {selectedIds.length > 0 ? `Eksportuj JSON (${selectedIds.length})` : 'Eksportuj JSON'}
          </Button>
          {selectedIds.length === 0 && (
            <Button
              type="button"
              size="sm"
              variant="secondary"
              disabled={exporting || enabledCount === 0}
              onClick={() => handleDownloadExport(true)}
              className="h-8 px-2.5 text-xs"
              title="Pobierz wyłącznie aktywne sygnatury jako plik JSON"
            >
              <Download className="h-3.5 w-3.5" />
              Tylko aktywne ({enabledCount})
            </Button>
          )}
        </div>
      </div>

      {/* Tabela sygnatur */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    checked={allFilteredSelected}
                    onCheckedChange={(v) => toggleSelectAllFiltered(Boolean(v))}
                    aria-label="Zaznacz wszystkie widoczne sygnatury"
                  />
                </TableHead>
                <TableHead>Nazwa</TableHead>
                <TableHead>Typ</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Wzorzec / Ścieżka</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Akcje</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredItems.map((sig) => (
                <TableRow
                  key={sig.id}
                  data-state={selectedIds.includes(sig.id) ? 'selected' : undefined}
                >
                  <TableCell>
                    <Checkbox
                      checked={selectedIds.includes(sig.id)}
                      onCheckedChange={(v) => toggleSelectOne(sig.id, Boolean(v))}
                      aria-label={`Zaznacz sygnaturę ${sig.name}`}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="font-medium text-foreground">{sig.name}</div>
                    {sig.description && <div className="text-[11px] text-muted-foreground">{sig.description}</div>}
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="font-mono">
                      {sig.match_type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={sig.severity} />
                  </TableCell>
                  <TableCell className="font-mono text-[11px] max-w-sm">
                    <div className="text-foreground break-all">
                      {sig.pattern || (sig.match_type === 'path_probe' ? '(dowolna treść — status + anty-soft-404)' : '—')}
                    </div>
                    {sig.probe_path && (
                      <div className="text-muted-foreground">
                        GET {sig.probe_path} (HTTP {sig.expected_status ?? '2xx/3xx'})
                      </div>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {canModify && (
                        <Switch
                          disabled={busyId === sig.id}
                          checked={sig.is_enabled}
                          onCheckedChange={() => handleToggle(sig)}
                        />
                      )}
                      <Badge variant={sig.is_enabled ? 'default' : 'outline'} className="font-mono">
                        {sig.is_enabled ? 'aktywna' : 'wyłączona'}
                      </Badge>
                    </div>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap space-x-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleCopySingle(sig)}
                      className="h-7 px-2"
                      title="Kopiuj JSON tej sygnatury"
                    >
                      {copiedId === sig.id ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    </Button>
                    {canModify && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busyId === sig.id}
                        onClick={() => handleStartEdit(sig)}
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
                        disabled={busyId === sig.id}
                        onClick={() => handleDelete(sig)}
                        className="h-7 px-2"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Usuń
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {filteredItems.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    Brak sygnatur pasujących do filtra.
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
