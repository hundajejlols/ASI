import {
  AlertCircle,
  Edit3,
  Eye,
  Filter,
  Play,
  Plus,
  Sparkles,
  X,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiFetch } from '../../api';
import type {
  GroupFacets,
  GroupFilterRules,
  GroupPreviewResponse,
  HostStatusValue,
  SavedGroupItem,
  UserRole,
} from '../../types';
import { HostStatusBadge } from '../Badges';
import { Alert, AlertDescription } from '../ui/alert';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Checkbox } from '../ui/checkbox';
import { Input } from '../ui/input';
import { Select } from '../ui/select';

interface Props {
  role: UserRole;
  canAdd: boolean;
  canModify: boolean;
  facets: GroupFacets | null;
  editingGroup: SavedGroupItem | null;
  onSaved: (message: string) => void;
  onAdHocScan: (rules: GroupFilterRules, label: string) => void;
  onCancelEdit: () => void;
  onClose: () => void;
}

const DEFAULT_STATUSES: HostStatusValue[] = ['online', 'unstable'];

export function buildEmptyRules(): GroupFilterRules {
  return {
    match_mode: 'all',
    technologies: [],
    ports: [],
    service_names: [],
    products: [],
    signature_ids: [],
    favicon_hashes: [],
    is_admin_panel: null,
    is_staging_env: null,
    statuses: [...DEFAULT_STATUSES],
    owner_units: [],
    tags: [],
    cidr_scope: null,
    exclude_ignored: true,
  };
}

function splitCsvStrings(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean)
    )
  );
}

function splitCsvPorts(raw: string): number[] {
  const out: number[] = [];
  for (const tok of raw.split(/[\s,;]+/)) {
    const t = tok.trim();
    if (!t) continue;
    const n = Number(t);
    if (Number.isInteger(n) && n >= 1 && n <= 65535 && !out.includes(n)) {
      out.push(n);
    }
  }
  return out.sort((a, b) => a - b);
}

function toggleCsvToken(currentRaw: string, token: string): string {
  const items = splitCsvStrings(currentRaw);
  const exists = items.some((x) => x.toLowerCase() === token.toLowerCase());
  const next = exists
    ? items.filter((x) => x.toLowerCase() !== token.toLowerCase())
    : [...items, token];
  return next.join(', ');
}

function togglePortToken(currentRaw: string, port: number): string {
  const items = splitCsvPorts(currentRaw);
  const exists = items.includes(port);
  const next = exists ? items.filter((p) => p !== port) : [...items, port].sort((a, b) => a - b);
  return next.join(', ');
}

export function GroupBuilderPanel({
  role,
  canAdd,
  canModify,
  facets,
  editingGroup,
  onSaved,
  onAdHocScan,
  onCancelEdit,
  onClose,
}: Props) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [environment, setEnvironment] = useState('prod');
  const [matchMode, setMatchMode] = useState<'all' | 'any'>('all');

  const [techsInput, setTechsInput] = useState('');
  const [portsInput, setPortsInput] = useState('');
  const [servicesInput, setServicesInput] = useState('');
  const [productsInput, setProductsInput] = useState('');
  const [selectedSigIds, setSelectedSigIds] = useState<string[]>([]);
  const [adminFilter, setAdminFilter] = useState<'any' | 'yes' | 'no'>('any');
  const [stagingFilter, setStagingFilter] = useState<'any' | 'yes' | 'no'>('any');
  const [statuses, setStatuses] = useState<HostStatusValue[]>([...DEFAULT_STATUSES]);
  const [ownerUnitsInput, setOwnerUnitsInput] = useState('');
  const [tagsInput, setTagsInput] = useState('');
  const [cidrScope, setCidrScope] = useState('');
  const [excludeIgnored, setExcludeIgnored] = useState(true);

  const [preview, setPreview] = useState<GroupPreviewResponse | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!editingGroup) return;
    const r = editingGroup.filter_rules || {};
    setName(editingGroup.name);
    setDescription(editingGroup.description || '');
    setEnvironment(editingGroup.environment || 'prod');
    setMatchMode(r.match_mode === 'any' ? 'any' : 'all');
    setTechsInput((r.technologies || []).join(', '));
    setPortsInput((r.ports || []).join(', '));
    setServicesInput((r.service_names || []).join(', '));
    setProductsInput((r.products || []).join(', '));
    setSelectedSigIds(r.signature_ids || []);
    setAdminFilter(r.is_admin_panel === true ? 'yes' : r.is_admin_panel === false ? 'no' : 'any');
    setStagingFilter(r.is_staging_env === true ? 'yes' : r.is_staging_env === false ? 'no' : 'any');
    setStatuses(r.statuses && r.statuses.length > 0 ? (r.statuses as HostStatusValue[]) : [...DEFAULT_STATUSES]);
    setOwnerUnitsInput((r.owner_units || []).join(', '));
    setTagsInput((r.tags || []).join(', '));
    setCidrScope(r.cidr_scope || '');
    setExcludeIgnored(r.exclude_ignored ?? true);
    setPreview(null);
    setError(null);
  }, [editingGroup]);

  function buildRules(): GroupFilterRules {
    return {
      match_mode: matchMode,
      technologies: splitCsvStrings(techsInput),
      ports: splitCsvPorts(portsInput),
      service_names: splitCsvStrings(servicesInput),
      products: splitCsvStrings(productsInput),
      signature_ids: selectedSigIds,
      favicon_hashes: [],
      is_admin_panel: adminFilter === 'yes' ? true : adminFilter === 'no' ? false : null,
      is_staging_env: stagingFilter === 'yes' ? true : stagingFilter === 'no' ? false : null,
      statuses: statuses.length > 0 ? statuses : ['online', 'unstable'],
      owner_units: splitCsvStrings(ownerUnitsInput),
      tags: splitCsvStrings(tagsInput),
      cidr_scope: cidrScope.trim() || null,
      exclude_ignored: excludeIgnored,
    };
  }

  function resetForm() {
    setName('');
    setDescription('');
    setEnvironment('prod');
    setMatchMode('all');
    setTechsInput('');
    setPortsInput('');
    setServicesInput('');
    setProductsInput('');
    setSelectedSigIds([]);
    setAdminFilter('any');
    setStagingFilter('any');
    setStatuses([...DEFAULT_STATUSES]);
    setOwnerUnitsInput('');
    setTagsInput('');
    setCidrScope('');
    setExcludeIgnored(true);
    setPreview(null);
    setError(null);
  }

  function toggleStatus(st: HostStatusValue) {
    setStatuses((prev) =>
      prev.includes(st) ? (prev.length > 1 ? prev.filter((x) => x !== st) : prev) : [...prev, st]
    );
  }

  function toggleSig(id: string) {
    setSelectedSigIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  async function handlePreview() {
    setPreviewing(true);
    setError(null);
    try {
      const rules = buildRules();
      const res = await apiFetch<GroupPreviewResponse>('/groups/preview', role, {
        method: 'POST',
        body: JSON.stringify(rules),
      });
      setPreview(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd podglądu dopasowanych hostów');
    } finally {
      setPreviewing(false);
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError('Podaj nazwę grupy dynamicznej.');
      return;
    }
    if (editingGroup ? !canModify : !canAdd) return;

    setSaving(true);
    setError(null);
    try {
      const rules = buildRules();
      const body = {
        name: name.trim(),
        description: description.trim() || null,
        environment,
        filter_rules: rules,
      };
      if (editingGroup) {
        await apiFetch(`/groups/${editingGroup.id}`, role, {
          method: 'PATCH',
          body: JSON.stringify(body),
        });
        resetForm();
        onCancelEdit();
        onSaved(`Zaktualizowano grupę dynamiczną "${body.name}".`);
      } else {
        await apiFetch('/groups', role, {
          method: 'POST',
          body: JSON.stringify(body),
        });
        resetForm();
        onSaved(`Utworzono grupę dynamiczną "${body.name}" (możesz ją teraz skanować i podpiąć pod harmonogram).`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu grupy dynamicznej');
    } finally {
      setSaving(false);
    }
  }

  const activeTechSet = new Set(splitCsvStrings(techsInput).map((s) => s.toLowerCase()));
  const activePortSet = new Set(splitCsvPorts(portsInput));
  const activeUnitSet = new Set(splitCsvStrings(ownerUnitsInput).map((s) => s.toLowerCase()));
  const activeTagSet = new Set(splitCsvStrings(tagsInput).map((s) => s.toLowerCase()));

  return (
    <Card>
      <CardHeader className="pb-3 flex-row flex-wrap items-center justify-between gap-2 space-y-0 border-b border-border">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm">
            {editingGroup ? `Edycja Smart Group: ${editingGroup.name}` : 'Kreator Grupy Dynamicznej (Smart Group)'}
          </CardTitle>
        </div>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={() => {
            if (editingGroup) {
              resetForm();
              onCancelEdit();
            } else {
              onClose();
            }
          }}
          className="h-7 px-2 text-xs"
        >
          <X className="h-3.5 w-3.5" />
          {editingGroup ? 'Anuluj edycję' : 'Zwiń'}
        </Button>
      </CardHeader>

      <CardContent className="p-4 space-y-4 text-xs">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <AlertDescription className="text-foreground">{error}</AlertDescription>
          </Alert>
        )}

        {/* Szybkie presety reguł */}
        {!editingGroup && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-muted-foreground flex items-center gap-1 mr-1">
              <Sparkles className="h-3 w-3" />
              Przykłady:
            </span>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-6 px-2 text-[10px]"
              onClick={() => {
                setName('WordPress — wszystkie hosty');
                setDescription('Hosty z wykrytym CMS WordPress');
                setTechsInput('WordPress');
                setPortsInput('');
                setAdminFilter('any');
                setStagingFilter('any');
              }}
            >
              Wszystkie WordPress
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-6 px-2 text-[10px]"
              onClick={() => {
                setName('Wystawiony port 8080');
                setDescription('Hosty z otwartym portem 8080/tcp');
                setTechsInput('');
                setPortsInput('8080');
                setAdminFilter('any');
                setStagingFilter('any');
              }}
            >
              Port 8080
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-6 px-2 text-[10px]"
              onClick={() => {
                setName('Panele administracyjne + Staging');
                setDescription('Wszystkie wystawione panele admina lub środowiska staging/test');
                setMatchMode('any');
                setTechsInput('');
                setPortsInput('');
                setAdminFilter('yes');
                setStagingFilter('yes');
              }}
            >
              Admin lub Staging
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-6 px-2 text-[10px]"
              onClick={() => {
                setName('Wystawione bazy / Redis');
                setDescription('Hosty z otwartymi portami baz danych lub brokerów');
                setTechsInput('');
                setPortsInput('3306, 5432, 6379, 27017, 9200');
                setAdminFilter('any');
                setStagingFilter('any');
              }}
            >
              Bazy danych / Redis
            </Button>
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-4">
          {/* Metadane grupy */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
            <label className="space-y-1 md:col-span-5">
              <span className="text-muted-foreground">Nazwa grupy dynamicznej *</span>
              <Input
                required
                maxLength={128}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="np. Serwery WordPress (AGH)"
              />
            </label>
            <label className="space-y-1 md:col-span-5">
              <span className="text-muted-foreground">Opis (opcjonalnie)</span>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Cel grupy / kontekst operacyjny"
              />
            </label>
            <label className="space-y-1 md:col-span-2">
              <span className="text-muted-foreground">Środowisko</span>
              <Select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                <option value="prod">prod</option>
                <option value="staging">staging</option>
                <option value="lab">lab</option>
                <option value="all">all</option>
              </Select>
            </label>
          </div>

          {/* Reguły dopasowania */}
          <div className="rounded-md border border-border bg-muted/30 p-3.5 space-y-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11px] font-medium uppercase tracking-wider text-foreground">
                Reguły automatycznego doboru hostów
              </span>
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-muted-foreground">Łączenie warunków:</span>
                <Button
                  type="button"
                  size="sm"
                  variant={matchMode === 'all' ? 'default' : 'outline'}
                  onClick={() => setMatchMode('all')}
                  className="h-6 px-2 text-[10px] font-mono"
                >
                  Wszystkie (ORAZ / AND)
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant={matchMode === 'any' ? 'default' : 'outline'}
                  onClick={() => setMatchMode('any')}
                  className="h-6 px-2 text-[10px] font-mono"
                >
                  Dowolny (LUB / OR)
                </Button>
              </div>
            </div>

            {/* Technologie + Porty */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="block space-y-1">
                  <span className="text-muted-foreground">Technologie / CMS (po przecinku)</span>
                  <Input
                    value={techsInput}
                    onChange={(e) => setTechsInput(e.target.value)}
                    placeholder="np. WordPress, PHP, nginx"
                    className="font-mono"
                  />
                </label>
                {facets && facets.technologies.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {facets.technologies.slice(0, 12).map((t) => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => setTechsInput((prev) => toggleCsvToken(prev, t))}
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                          activeTechSet.has(t.toLowerCase())
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border bg-background text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="space-y-1.5">
                <label className="block space-y-1">
                  <span className="text-muted-foreground">Otwarte porty (po przecinku)</span>
                  <Input
                    value={portsInput}
                    onChange={(e) => setPortsInput(e.target.value)}
                    placeholder="np. 8080, 8443, 443"
                    className="font-mono"
                  />
                </label>
                {facets && facets.ports.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {facets.ports.slice(0, 14).map((p) => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => setPortsInput((prev) => togglePortToken(prev, p))}
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                          activePortSet.has(p)
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border bg-background text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Usługi, Produkty, Admin, Staging */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <label className="space-y-1">
                <span className="text-muted-foreground">Nazwy usług (np. http, ssh, redis)</span>
                <Input
                  value={servicesInput}
                  onChange={(e) => setServicesInput(e.target.value)}
                  placeholder="np. http, https"
                  className="font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-muted-foreground">Produkt / baner (zawiera)</span>
                <Input
                  value={productsInput}
                  onChange={(e) => setProductsInput(e.target.value)}
                  placeholder="np. nginx, OpenSSH"
                  className="font-mono"
                />
              </label>
              <label className="space-y-1">
                <span className="text-muted-foreground">Panel administracyjny</span>
                <Select
                  value={adminFilter}
                  onChange={(e) => setAdminFilter(e.target.value as 'any' | 'yes' | 'no')}
                >
                  <option value="any">Dowolnie</option>
                  <option value="yes">Tylko panele admina</option>
                  <option value="no">Bez paneli admina</option>
                </Select>
              </label>
              <label className="space-y-1">
                <span className="text-muted-foreground">Środowisko Staging / Dev</span>
                <Select
                  value={stagingFilter}
                  onChange={(e) => setStagingFilter(e.target.value as 'any' | 'yes' | 'no')}
                >
                  <option value="any">Dowolnie</option>
                  <option value="yes">Tylko staging / dev</option>
                  <option value="no">Bez staging / dev</option>
                </Select>
              </label>
            </div>

            {/* Jednostka, Tagi, Zakres CIDR */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="block space-y-1">
                  <span className="text-muted-foreground">Jednostka / właściciel (owner_unit)</span>
                  <Input
                    value={ownerUnitsInput}
                    onChange={(e) => setOwnerUnitsInput(e.target.value)}
                    placeholder="np. WIEiT, CBI"
                  />
                </label>
                {facets && facets.owner_units.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {facets.owner_units.slice(0, 8).map((u) => (
                      <button
                        key={u}
                        type="button"
                        onClick={() => setOwnerUnitsInput((prev) => toggleCsvToken(prev, u))}
                        className={`rounded border px-1.5 py-0.5 text-[10px] ${
                          activeUnitSet.has(u.toLowerCase())
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border bg-background text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {u}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="space-y-1">
                <label className="block space-y-1">
                  <span className="text-muted-foreground">Tagi z asset_overrides (po przecinku)</span>
                  <Input
                    value={tagsInput}
                    onChange={(e) => setTagsInput(e.target.value)}
                    placeholder="np. krytyczny, web"
                    className="font-mono"
                  />
                </label>
                {facets && facets.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {facets.tags.slice(0, 8).map((t) => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => setTagsInput((prev) => toggleCsvToken(prev, t))}
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                          activeTagSet.has(t.toLowerCase())
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border bg-background text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        #{t}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <label className="space-y-1">
                <span className="text-muted-foreground">Zawężenie do podsieci CIDR (opcjonalnie)</span>
                <Input
                  value={cidrScope}
                  onChange={(e) => setCidrScope(e.target.value)}
                  placeholder="np. 172.28.0.0/24"
                  className="font-mono"
                />
              </label>
            </div>

            {/* Dopasowane sygnatury pasywne */}
            {facets && facets.signatures.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-muted-foreground block">Dopasowane sygnatury pasywne (opcjonalnie):</span>
                <div className="flex flex-wrap gap-1.5">
                  {facets.signatures.map((s) => {
                    const active = selectedSigIds.includes(s.id);
                    return (
                      <button
                        key={s.id}
                        type="button"
                        onClick={() => toggleSig(s.id)}
                        className={`rounded border px-2 py-0.5 text-[10px] transition-colors ${
                          active
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border bg-background text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {s.name}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Status hostów i exclude_ignored */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border/70">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-muted-foreground">Status hostów:</span>
                {(['online', 'unstable', 'offline'] as const).map((st) => (
                  <label key={st} className="flex items-center gap-1.5 cursor-pointer font-mono text-foreground">
                    <Checkbox checked={statuses.includes(st)} onCheckedChange={() => toggleStatus(st)} />
                    <span>{st}</span>
                  </label>
                ))}
              </div>
              <label className="flex items-center gap-1.5 cursor-pointer text-foreground">
                <Checkbox
                  checked={excludeIgnored}
                  onCheckedChange={(v) => setExcludeIgnored(Boolean(v))}
                />
                <span>Pomijaj hosty ignorowane (asset_overrides)</span>
              </label>
            </div>
          </div>

          {/* Podgląd dopasowanych hostów na żywo */}
          {preview && (
            <div className="rounded-md border border-border bg-card p-3 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <Badge variant={preview.total_hosts > 0 ? 'default' : 'outline'}>
                    Dopasowano hostów: {preview.total_hosts}
                  </Badge>
                  {preview.suggested_ports_spec && (
                    <Badge variant="secondary">Porty w grupie: {preview.suggested_ports_spec}</Badge>
                  )}
                </div>
                {canAdd && preview.total_hosts > 0 && (
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    onClick={() => onAdHocScan(buildRules(), name.trim() || 'Podgląd Smart Group')}
                    className="h-7 px-2.5 text-[11px]"
                  >
                    <Play className="h-3 w-3" />
                    Skanuj bez zapisywania ({preview.total_hosts})
                  </Button>
                )}
              </div>
              {preview.hosts.length > 0 ? (
                <div className="max-h-40 overflow-y-auto divide-y divide-border/60 rounded border border-border">
                  {preview.hosts.slice(0, 30).map((h) => (
                    <div
                      key={h.id}
                      className="flex flex-wrap items-center justify-between gap-2 px-2.5 py-1.5 text-[11px]"
                    >
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-semibold text-foreground">{h.ip_address}</span>
                        {h.hostname && <span className="text-muted-foreground">({h.hostname})</span>}
                        <HostStatusBadge status={h.status} missedScans={h.missed_scans} />
                      </div>
                      <div className="flex flex-wrap items-center gap-1 font-mono text-[10px]">
                        {h.open_ports.map((p) => (
                          <Badge key={p} variant="outline" className="text-[10px] px-1.5 py-0">
                            :{p}
                          </Badge>
                        ))}
                        {h.technologies.slice(0, 4).map((t) => (
                          <Badge key={t} variant="secondary" className="text-[10px] px-1.5 py-0">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground text-xs">
                  Żaden host w bazie nie spełnia obecnie tej kombinacji reguł (możesz mimo to zapisać grupę — wypełni się po kolejnych skanach).
                </p>
              )}
            </div>
          )}

          {/* Akcje formularza */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="outline" disabled={previewing} onClick={handlePreview}>
                <Eye className="h-3.5 w-3.5" />
                {previewing ? 'Sprawdzanie...' : 'Podgląd dopasowanych hostów'}
              </Button>
              <Button type="submit" disabled={saving}>
                {editingGroup ? <Edit3 className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
                {saving
                  ? 'Zapisywanie...'
                  : editingGroup
                  ? 'Zapisz zmiany grupy'
                  : 'Zapisz jako Smart Group'}
              </Button>
            </div>
            {!editingGroup && (
              <Button type="button" variant="ghost" size="sm" onClick={resetForm}>
                Wyczyść reguły
              </Button>
            )}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
