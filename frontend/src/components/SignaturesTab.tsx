import { AlertCircle, CheckCircle2, Edit3, Plus, Trash2, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type { Severity, SignatureItem, SignatureMatchType, UserRole } from '../types';
import { SeverityBadge } from './Badges';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Switch } from './ui/checkbox';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

interface Props {
  role: UserRole;
}

export function SignaturesTab({ role }: Props) {
  const [items, setItems] = useState<SignatureItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<Severity>('low');
  const [matchType, setMatchType] = useState<SignatureMatchType>('header');
  const [pattern, setPattern] = useState('');
  const [probePath, setProbePath] = useState('');
  const [expectedStatus, setExpectedStatus] = useState('200');

  const canAdd = hasPermission(role, 'add');
  const canModify = hasPermission(role, 'modify');
  const canDelete = hasPermission(role, 'delete');

  async function loadSignatures() {
    try {
      const data = await apiFetch<SignatureItem[]>('/signatures', role);
      setItems(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania sygnatur');
    }
  }

  useEffect(() => {
    loadSignatures();
  }, [role]);

  function resetForm() {
    setEditingId(null);
    setName('');
    setDescription('');
    setSeverity('low');
    setMatchType('header');
    setPattern('');
    setProbePath('');
    setExpectedStatus('200');
  }

  function startEdit(sig: SignatureItem) {
    setEditingId(sig.id);
    setName(sig.name);
    setDescription(sig.description || '');
    setSeverity(sig.severity);
    setMatchType(sig.match_type);
    setPattern(sig.pattern);
    setProbePath(sig.probe_path || '');
    setExpectedStatus(sig.expected_status ? String(sig.expected_status) : '200');
    setError(null);
    setNotice(null);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !pattern.trim()) return;
    if (editingId ? !canModify : !canAdd) return;
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      const bodyPayload = {
        name: name.trim(),
        description: description.trim() || null,
        severity,
        match_type: matchType,
        pattern: pattern.trim(),
        probe_path: matchType === 'path_probe' ? probePath.trim() || null : null,
        expected_status: matchType === 'path_probe' && expectedStatus ? Number(expectedStatus) : null,
      };
      if (editingId) {
        await apiFetch(`/signatures/${editingId}`, role, {
          method: 'PATCH',
          body: JSON.stringify(bodyPayload),
        });
        setNotice(`Zaktualizowano sygnaturę: "${name.trim()}".`);
      } else {
        await apiFetch('/signatures', role, {
          method: 'POST',
          body: JSON.stringify({ ...bodyPayload, is_enabled: true }),
        });
        setNotice(`Dodano nową sygnaturę pasywną: "${name.trim()}".`);
      }
      resetForm();
      await loadSignatures();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu sygnatury');
    } finally {
      setSubmitting(false);
    }
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

  async function handleDelete(id: string) {
    if (!canDelete) return;
    setError(null);
    setNotice(null);
    setBusyId(id);
    try {
      await apiFetch(`/signatures/${id}`, role, { method: 'DELETE' });
      if (editingId === id) resetForm();
      setNotice('Usunięto sygnaturę.');
      await loadSignatures();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania sygnatury');
    } finally {
      setBusyId(null);
    }
  }

  const showForm = editingId ? canModify : canAdd;

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

      {showForm && (
        <Card>
          <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
            <CardTitle>{editingId ? 'Edycja sygnatury' : 'Nowa sygnatura'}</CardTitle>
            {editingId && (
              <Button size="sm" variant="ghost" onClick={resetForm}>
                <X className="h-3.5 w-3.5" />
                Anuluj edycję
              </Button>
            )}
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <Input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Nazwa reguły"
                />
                <Select
                  value={matchType}
                  onChange={(e) => setMatchType(e.target.value as SignatureMatchType)}
                >
                  <option value="header">header</option>
                  <option value="cookie">cookie</option>
                  <option value="favicon_hash">favicon_hash</option>
                  <option value="html_fragment">html_fragment</option>
                  <option value="path_probe">path_probe (tylko GET)</option>
                  <option value="footer_version">footer_version</option>
                </Select>
                <Select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as Severity)}
                >
                  <option value="info">info</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </Select>
                <Input
                  required
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="Wzorzec (RE2 regex / hash MMH3)"
                  className="font-mono"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Opis (opcjonalnie)"
                />
                {matchType === 'path_probe' && (
                  <>
                    <Input
                      value={probePath}
                      onChange={(e) => setProbePath(e.target.value)}
                      placeholder="Ścieżka np. /status"
                      className="font-mono"
                    />
                    <Input
                      type="number"
                      value={expectedStatus}
                      onChange={(e) => setExpectedStatus(e.target.value)}
                      placeholder="Oczekiwany kod HTTP (np. 200)"
                      className="font-mono"
                    />
                  </>
                )}
              </div>

              <Button type="submit" disabled={submitting}>
                {editingId ? <Edit3 className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
                {submitting ? 'Zapisywanie...' : editingId ? 'Zapisz zmiany' : 'Dodaj sygnaturę'}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nazwa</TableHead>
                <TableHead>Typ</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Wzorzec / Ścieżka</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Akcje</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((sig) => (
                <TableRow key={sig.id}>
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
                  <TableCell className="font-mono text-[11px]">
                    <div className="text-foreground">{sig.pattern}</div>
                    {sig.probe_path && (
                      <div className="text-muted-foreground">
                        GET {sig.probe_path} (HTTP {sig.expected_status ?? '2xx'})
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
                    {canModify && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busyId === sig.id}
                        onClick={() => startEdit(sig)}
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
                        onClick={() => handleDelete(sig.id)}
                        className="h-7 px-2"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Usuń
                      </Button>
                    )}
                    {!canModify && !canDelete && <span className="text-muted-foreground">—</span>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
