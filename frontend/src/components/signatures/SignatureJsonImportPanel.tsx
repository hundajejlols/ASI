import {
  AlertCircle,
  CheckCircle2,
  ClipboardPaste,
  FileJson,
  FileUp,
  Play,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react';
import { useRef, useState } from 'react';
import { apiFetch } from '../../api';
import type { SignatureImportItemStatus, SignatureImportResponse, UserRole } from '../../types';
import { SeverityBadge } from '../Badges';
import { Alert, AlertDescription } from '../ui/alert';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Textarea } from '../ui/textarea';
import { EXAMPLE_IMPORT_JSON } from './signatureBuilderUtils';

interface Props {
  role: UserRole;
  canModify: boolean;
  onImported: (message: string) => void;
  onClose?: () => void;
}

type ConflictMode = 'skip' | 'overwrite' | 'error';

function statusBadgeMeta(st: SignatureImportItemStatus): { label: string; variant: 'default' | 'secondary' | 'outline' } {
  switch (st) {
    case 'created':
      return { label: 'DODANA', variant: 'default' };
    case 'would_create':
      return { label: 'NOWA', variant: 'default' };
    case 'updated':
      return { label: 'ZAKTUALIZOWANA', variant: 'secondary' };
    case 'would_update':
      return { label: 'NADPISZE', variant: 'secondary' };
    case 'skipped':
    case 'would_skip':
      return { label: 'POMINIĘTA', variant: 'outline' };
    case 'error':
      return { label: 'BŁĄD', variant: 'outline' };
  }
}

export function SignatureJsonImportPanel({ role, canModify, onImported, onClose }: Props) {
  const [rawJson, setRawJson] = useState('');
  const [onConflict, setOnConflict] = useState<ConflictMode>('skip');
  const [isDragging, setIsDragging] = useState(false);
  const [busyMode, setBusyMode] = useState<'dry_run' | 'import' | null>(null);
  const [result, setResult] = useState<SignatureImportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function handleFormatJson() {
    setError(null);
    if (!rawJson.trim()) return;
    try {
      const parsed = JSON.parse(rawJson);
      setRawJson(JSON.stringify(parsed, null, 2));
    } catch (e) {
      setError(`Niepoprawna składnia JSON: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  async function loadFile(file: File) {
    setError(null);
    setResult(null);
    try {
      const text = await file.text();
      setRawJson(text);
    } catch {
      setError('Nie udało się odczytać pliku JSON.');
    }
  }

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      await loadFile(file);
    }
    e.target.value = '';
  }

  async function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await loadFile(file);
    }
  }

  async function runImport(dryRun: boolean) {
    setError(null);
    setResult(null);
    const trimmed = rawJson.trim();
    if (!trimmed) {
      setError('Wklej JSON z sygnaturami albo wczytaj plik .json.');
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      setError(`Błąd składni JSON: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }

    setBusyMode(dryRun ? 'dry_run' : 'import');
    try {
      const params = new URLSearchParams({
        on_conflict: onConflict,
        dry_run: String(dryRun),
      });
      const res = await apiFetch<SignatureImportResponse>(
        `/signatures/import?${params.toString()}`,
        role,
        {
          method: 'POST',
          body: JSON.stringify(parsed),
        }
      );
      setResult(res);
      if (!dryRun) {
        const { created, updated, skipped, errors } = res.summary;
        onImported(
          `Import JSON zakończony: dodano ${created}, zaktualizowano ${updated}, pominięto ${skipped}, błędów ${errors}.`
        );
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Błąd importu JSON';
      // W trybie on_conflict=error backend zwraca obiekt JSON z polami message/summary/items
      try {
        const parsedErr = JSON.parse(msg);
        if (parsedErr && typeof parsedErr === 'object' && Array.isArray(parsedErr.items)) {
          setResult({
            dry_run: false,
            on_conflict: onConflict,
            summary: parsedErr.summary,
            items: parsedErr.items,
          });
          setError(String(parsedErr.message || 'Import zatrzymany z powodu konfliktów/błędów.'));
          return;
        }
      } catch {
        // plain string message
      }
      setError(msg);
    } finally {
      setBusyMode(null);
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3 flex-row flex-wrap items-center justify-between gap-2 space-y-0 border-b border-border">
        <div>
          <CardTitle className="text-sm flex items-center gap-2">
            <FileJson className="h-4 w-4 text-muted-foreground" />
            Import sygnatur z JSON (wklej tekst lub wgraj plik .json)
          </CardTitle>
          <CardDescription>
            Akceptuje eksport Janus ASI (<code>{`{"signatures": [...]}`}</code>), gołą tablicę (<code>[...]</code>) oraz
            pojedynczą regułę — z automatycznym mapowaniem popularnych aliasów pól (<code>type</code>,{' '}
            <code>path</code>, <code>status</code>, <code>regex</code>).
          </CardDescription>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            onChange={handleFileSelect}
            className="hidden"
          />
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => fileInputRef.current?.click()}
            className="h-7 px-2.5 text-[11px]"
          >
            <FileUp className="h-3.5 w-3.5" />
            Wczytaj plik .json
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              setRawJson(EXAMPLE_IMPORT_JSON);
              setError(null);
              setResult(null);
            }}
            className="h-7 px-2.5 text-[11px]"
          >
            <Sparkles className="h-3.5 w-3.5" />
            Wklej przykład
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={handleFormatJson}
            disabled={!rawJson.trim()}
            className="h-7 px-2 text-[11px]"
          >
            Formatuj
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => {
              setRawJson('');
              setResult(null);
              setError(null);
            }}
            disabled={!rawJson && !result}
            className="h-7 px-2 text-[11px]"
            title="Wyczyść"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
          {onClose && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={onClose}
              className="h-7 px-2 text-xs"
              title="Zwiń panel importu"
            >
              <X className="h-3.5 w-3.5" />
              Zwiń
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="p-4 space-y-4 text-xs">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <AlertDescription className="text-foreground">{error}</AlertDescription>
          </Alert>
        )}

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={`rounded-md transition-colors ${
            isDragging ? 'ring-2 ring-primary bg-muted/50' : ''
          }`}
        >
          <Textarea
            rows={10}
            value={rawJson}
            onChange={(e) => setRawJson(e.target.value)}
            placeholder={`Wklej tutaj JSON z sygnaturami (albo upuść plik .json)...\n\nPrzykład:\n[\n  {\n    "name": "Custom Admin Path",\n    "match_type": "path_probe",\n    "probe_path": "/admin-panel",\n    "expected_status": 200,\n    "severity": "medium",\n    "pattern": "(?i)admin"\n  }\n]`}
            className="font-mono text-[11px] leading-relaxed"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-muted-foreground mr-1">Gdy nazwa już istnieje:</span>
            {(
              [
                ['skip', 'Pomiń (skip)'],
                ['overwrite', 'Nadpisz (overwrite)'],
                ['error', 'Przerwij (error)'],
              ] as const
            ).map(([mode, label]) => (
              <Button
                key={mode}
                type="button"
                size="sm"
                variant={onConflict === mode ? 'default' : 'outline'}
                disabled={mode === 'overwrite' && !canModify}
                onClick={() => setOnConflict(mode)}
                className="h-7 px-2.5 text-[11px] font-mono"
              >
                {label}
              </Button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={busyMode !== null || !rawJson.trim()}
              onClick={() => runImport(true)}
            >
              <ClipboardPaste className="h-3.5 w-3.5" />
              {busyMode === 'dry_run' ? 'Walidacja...' : 'Waliduj / Podgląd (Dry-Run)'}
            </Button>
            <Button
              type="button"
              disabled={busyMode !== null || !rawJson.trim()}
              onClick={() => runImport(false)}
            >
              <Play className="h-3.5 w-3.5" />
              {busyMode === 'import' ? 'Importowanie...' : 'Importuj sygnatury'}
            </Button>
          </div>
        </div>

        {result && (
          <div className="space-y-2.5 pt-2 border-t border-border">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 font-medium text-foreground">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>{result.dry_run ? 'Wynik walidacji (Dry-Run — bez zapisu):' : 'Raport importu JSON:'}</span>
              </div>
              <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                <Badge variant="secondary">Łącznie: {result.summary.total}</Badge>
                <Badge variant="default">
                  {result.dry_run ? 'Nowe' : 'Dodano'}: {result.summary.created}
                </Badge>
                {result.summary.updated > 0 && (
                  <Badge variant="secondary">
                    {result.dry_run ? 'Nadpisze' : 'Zaktualizowano'}: {result.summary.updated}
                  </Badge>
                )}
                {result.summary.skipped > 0 && (
                  <Badge variant="outline">Pominięto: {result.summary.skipped}</Badge>
                )}
                {result.summary.errors > 0 && (
                  <Badge variant="outline" className="border-foreground font-bold">
                    Błędy: {result.summary.errors}
                  </Badge>
                )}
              </div>
            </div>

            <div className="rounded-md border border-border overflow-hidden max-h-64 overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>#</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Nazwa</TableHead>
                    <TableHead>Typ / Severity</TableHead>
                    <TableHead>Wzorzec / Komunikat</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.items.map((it) => {
                    const meta = statusBadgeMeta(it.status);
                    return (
                      <TableRow key={`${it.index}-${it.name}`}>
                        <TableCell className="font-mono text-muted-foreground">{it.index + 1}</TableCell>
                        <TableCell>
                          <Badge
                            variant={meta.variant}
                            className={`font-mono text-[10px] ${
                              it.status === 'error' ? 'border-foreground font-bold' : ''
                            }`}
                          >
                            {meta.label}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium text-foreground">{it.name}</TableCell>
                        <TableCell className="whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            {it.match_type && (
                              <Badge variant="secondary" className="font-mono text-[10px]">
                                {it.match_type}
                              </Badge>
                            )}
                            {it.severity && <SeverityBadge severity={it.severity} />}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-[11px]">
                          {it.pattern && <div className="text-foreground truncate max-w-sm">{it.pattern}</div>}
                          <div className="text-muted-foreground font-sans text-[11px]">{it.message}</div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
