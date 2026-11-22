import {
  AlertCircle,
  Eye,
  Layers,
  Lock,
  Network,
  Plus,
  Save,
  Search,
  Server,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { apiFetch } from '../api';
import type {
  HostSummary,
  RoleItem,
  SavedGroupItem,
  UserItem,
  UserRole,
  UserScopeConfig,
  UserScopeSummary,
} from '../types';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Checkbox, Switch } from './ui/checkbox';
import { Input } from './ui/input';
import { Select } from './ui/select';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from './ui/sheet';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserItem | null;
  role: UserRole;
  roles: RoleItem[];
  currentUsername: string | null;
  onSaved: (updated: UserItem) => void;
  onDeleted: (deletedId: string, username: string) => void;
}

const EMPTY_SCOPE: UserScopeConfig = {
  ips: [],
  cidrs: [],
  ip_ranges: [],
  group_ids: [],
  host_ids: [],
};

function normalizeScope(raw?: Partial<UserScopeConfig> | null): UserScopeConfig {
  return {
    ips: Array.isArray(raw?.ips) ? [...raw.ips] : [],
    cidrs: Array.isArray(raw?.cidrs) ? [...raw.cidrs] : [],
    ip_ranges: Array.isArray(raw?.ip_ranges) ? [...raw.ip_ranges] : [],
    group_ids: Array.isArray(raw?.group_ids) ? [...raw.group_ids] : [],
    host_ids: Array.isArray(raw?.host_ids) ? [...raw.host_ids] : [],
  };
}

export function UserEditSheet({
  open,
  onOpenChange,
  user,
  role,
  roles,
  currentUsername,
  onSaved,
  onDeleted,
}: Props) {
  const [email, setEmail] = useState('');
  const [roleName, setRoleName] = useState('read_only');
  const [isActive, setIsActive] = useState(true);
  const [newPassword, setNewPassword] = useState('');
  const [scopeRestricted, setScopeRestricted] = useState(false);
  const [scope, setScope] = useState<UserScopeConfig>(EMPTY_SCOPE);

  const [networkInput, setNetworkInput] = useState('');
  const [groupSearch, setGroupSearch] = useState('');
  const [hostSearch, setHostSearch] = useState('');

  const [availableGroups, setAvailableGroups] = useState<SavedGroupItem[]>([]);
  const [availableHosts, setAvailableHosts] = useState<HostSummary[]>([]);
  const [loadingCatalog, setLoadingCatalog] = useState(false);

  const [previewSummary, setPreviewSummary] = useState<UserScopeSummary | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Wypełnij formularz przy otwarciu dla konkretnego użytkownika
  useEffect(() => {
    if (!open || !user) return;
    setEmail(user.email);
    setRoleName(user.role);
    setIsActive(user.is_active);
    setNewPassword('');
    setScopeRestricted(Boolean(user.scope_restricted));
    setScope(normalizeScope(user.allowed_scope));
    setPreviewSummary(user.scope_summary ?? null);
    setPreviewError(null);
    setNetworkInput('');
    setGroupSearch('');
    setHostSearch('');
    setConfirmDelete(false);
    setError(null);
  }, [open, user]);

  // Załaduj katalog grup i odkrytych hostów do wyklikania
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoadingCatalog(true);
    Promise.all([
      apiFetch<SavedGroupItem[]>('/groups?include_static=true', role).catch(() => []),
      apiFetch<HostSummary[]>('/hosts?limit=500', role).catch(() => []),
    ])
      .then(([grpRes, hostRes]) => {
        if (cancelled) return;
        setAvailableGroups(grpRes);
        setAvailableHosts(hostRes);
      })
      .finally(() => {
        if (!cancelled) setLoadingCatalog(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, role]);

  // Podgląd na żywo, ile hostów zobaczy użytkownik po zmianie zakresu
  useEffect(() => {
    if (!open || !user || !scopeRestricted) {
      setPreviewError(null);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      setLoadingPreview(true);
      apiFetch<{ scope_summary: UserScopeSummary }>('/rbac/users/scope-preview', role, {
        method: 'POST',
        body: JSON.stringify({
          scope_restricted: true,
          allowed_scope: scope,
        }),
      })
        .then((res) => {
          if (cancelled) return;
          setPreviewSummary(res.scope_summary);
          setPreviewError(null);
        })
        .catch((err) => {
          if (cancelled) return;
          setPreviewError(err instanceof Error ? err.message : 'Nieprawidłowy wpis w zakresie');
        })
        .finally(() => {
          if (!cancelled) setLoadingPreview(false);
        });
    }, 220);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [open, user, role, scopeRestricted, scope]);

  const filteredGroups = useMemo(() => {
    const q = groupSearch.trim().toLowerCase();
    if (!q) return availableGroups;
    return availableGroups.filter(
      (g) =>
        g.name.toLowerCase().includes(q) ||
        (g.description || '').toLowerCase().includes(q) ||
        g.sample_ips.some((ip) => ip.includes(q))
    );
  }, [availableGroups, groupSearch]);

  const filteredHosts = useMemo(() => {
    const q = hostSearch.trim().toLowerCase();
    if (!q) return availableHosts;
    return availableHosts.filter(
      (h) =>
        h.ip_address.toLowerCase().includes(q) ||
        (h.hostname || '').toLowerCase().includes(q) ||
        (h.override?.custom_label || '').toLowerCase().includes(q) ||
        (h.override?.owner_unit || '').toLowerCase().includes(q) ||
        (h.technologies || []).some((t) => t.toLowerCase().includes(q))
    );
  }, [availableHosts, hostSearch]);

  function handleAddNetworkTokens() {
    const rawTokens = networkInput
      .split(/[\n,;]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (rawTokens.length === 0) return;

    setScope((prev) => {
      const nextIps = [...prev.ips];
      const nextCidrs = [...prev.cidrs];
      const nextRanges = [...prev.ip_ranges];

      for (const token of rawTokens) {
        if (token.includes('/')) {
          if (!nextCidrs.includes(token)) nextCidrs.push(token);
        } else if (token.includes('-')) {
          const norm = token
            .split('-', 2)
            .map((p) => p.trim())
            .join('-');
          if (!nextRanges.includes(norm)) nextRanges.push(norm);
        } else {
          if (!nextIps.includes(token)) nextIps.push(token);
        }
      }
      return {
        ...prev,
        ips: nextIps,
        cidrs: nextCidrs,
        ip_ranges: nextRanges,
      };
    });
    setNetworkInput('');
  }

  function removeScopeToken(kind: 'ips' | 'cidrs' | 'ip_ranges', val: string) {
    setScope((prev) => ({
      ...prev,
      [kind]: prev[kind].filter((item) => item !== val),
    }));
  }

  function toggleGroupId(gid: string) {
    setScope((prev) => ({
      ...prev,
      group_ids: prev.group_ids.includes(gid)
        ? prev.group_ids.filter((id) => id !== gid)
        : [...prev.group_ids, gid],
    }));
  }

  function toggleHostId(hid: string) {
    setScope((prev) => ({
      ...prev,
      host_ids: prev.host_ids.includes(hid)
        ? prev.host_ids.filter((id) => id !== hid)
        : [...prev.host_ids, hid],
    }));
  }

  function selectAllFilteredHosts() {
    setScope((prev) => {
      const merged = new Set(prev.host_ids);
      for (const h of filteredHosts) merged.add(h.id);
      return { ...prev, host_ids: Array.from(merged) };
    });
  }

  function clearSelectedHosts() {
    setScope((prev) => ({ ...prev, host_ids: [] }));
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!user) return;
    setSaving(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        email: email.trim(),
        role_name: roleName,
        is_active: isActive,
        scope_restricted: scopeRestricted,
        allowed_scope: scope,
      };
      if (newPassword.trim()) {
        body.password = newPassword.trim();
      }
      const updated = await apiFetch<UserItem>(`/rbac/users/${user.id}`, role, {
        method: 'PATCH',
        body: JSON.stringify(body),
      });
      onSaved(updated);
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd zapisu ustawień konta');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!user) return;
    if (!confirmDelete) {
      setConfirmDelete(true);
      return;
    }
    setDeleting(true);
    setError(null);
    try {
      await apiFetch(`/rbac/users/${user.id}`, role, { method: 'DELETE' });
      onDeleted(user.id, user.username);
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania konta');
      setConfirmDelete(false);
    } finally {
      setDeleting(false);
    }
  }

  const totalNetEntries = scope.ips.length + scope.cidrs.length + scope.ip_ranges.length;
  const isSelf = Boolean(user && currentUsername && user.username === currentUsername);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="max-w-2xl">
        {user && (
          <form onSubmit={handleSave} className="flex flex-col h-full min-h-0">
            <SheetHeader className="pb-3 border-b border-border/60 shrink-0">
              <div className="flex flex-wrap items-center gap-2">
                <SheetTitle className="font-mono">Ustawienia konta: {user.username}</SheetTitle>
                <Badge variant="secondary" className="font-mono text-[10px]">
                  {roleName}
                </Badge>
                <Badge variant={isActive ? 'outline' : 'default'} className="font-mono text-[10px]">
                  {isActive ? 'aktywne' : 'zablokowane'}
                </Badge>
              </div>
              <SheetDescription>
                Edycja roli RBAC oraz ograniczania widoczności hostów (grupy, IP, podsieci CIDR, zakresy IP i wybrane hosty).
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto py-4 pr-1 space-y-5 text-xs">
              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                  <AlertDescription className="text-foreground">{error}</AlertDescription>
                </Alert>
              )}

              {/* Sekcja 1: Podstawowe ustawienia konta */}
              <div className="rounded-lg border border-border bg-muted/20 p-3.5 space-y-3">
                <div className="text-xs font-medium text-foreground">1. Dane i uprawnienia konta</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <label className="space-y-1">
                    <span className="text-muted-foreground">Email</span>
                    <Input
                      required
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="bg-background"
                    />
                  </label>
                  <label className="space-y-1">
                    <span className="text-muted-foreground">Rola RBAC</span>
                    <Select
                      value={roleName}
                      onChange={(e) => setRoleName(e.target.value)}
                      className="font-mono bg-background"
                    >
                      {roles.map((r) => (
                        <option key={r.name} value={r.name}>
                          {r.name}
                        </option>
                      ))}
                    </Select>
                  </label>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-end">
                  <label className="space-y-1">
                    <span className="text-muted-foreground">Nowe hasło (opcjonalnie)</span>
                    <Input
                      type="password"
                      minLength={6}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Zostaw puste, aby nie zmieniać"
                      className="bg-background"
                    />
                  </label>
                  <div className="flex items-center justify-between rounded-md border border-border bg-background px-3 py-2">
                    <span className="text-foreground font-medium">Konto aktywne</span>
                    <Switch
                      checked={isActive}
                      disabled={isSelf}
                      onCheckedChange={(v) => setIsActive(Boolean(v))}
                    />
                  </div>
                </div>
              </div>

              {/* Sekcja 2: Ograniczanie widoczności hostów (Asset Scope) */}
              <div className="rounded-lg border border-border p-3.5 space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-1.5 text-xs font-medium text-foreground">
                      <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                      <span>2. Ograniczona widoczność hostów (Zakres konta)</span>
                    </div>
                    <p className="text-[11px] text-muted-foreground leading-snug">
                      Gdy włączone, użytkownik widzi i może skanować/eksportować wyłącznie hosty z przypisanych grup, IP, podsieci CIDR lub zakresów.
                    </p>
                  </div>
                  <Switch
                    checked={scopeRestricted}
                    onCheckedChange={(v) => setScopeRestricted(Boolean(v))}
                    aria-label="Ogranicz widoczność hostów dla tego konta"
                  />
                </div>

                {!scopeRestricted ? (
                  <div className="rounded-md border border-border bg-muted/30 px-3 py-2.5 text-[11px] text-muted-foreground flex items-center gap-2">
                    <Eye className="h-3.5 w-3.5 shrink-0" />
                    <span>
                      <strong className="text-foreground">Pełny dostęp</strong> — konto widzi wszystkie hosty, zmiany, grupy i raporty w systemie (zgodnie z rolą RBAC).
                    </span>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Podgląd na żywo */}
                    <div className="rounded-md border border-foreground/25 bg-muted/40 p-3 space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 font-medium text-foreground">
                          <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                          <span>Podgląd widoczności na żywo</span>
                        </div>
                        <Badge
                          variant={
                            previewSummary && previewSummary.matched_hosts_count > 0 ? 'default' : 'outline'
                          }
                          className="font-mono text-[10px]"
                        >
                          {loadingPreview
                            ? 'Przeliczanie...'
                            : `${previewSummary?.matched_hosts_count ?? 0} odkrytych hostów w DB`}
                        </Badge>
                      </div>

                      {previewError ? (
                        <p className="text-[11px] text-foreground font-mono">Błąd walidacji zakresu: {previewError}</p>
                      ) : previewSummary && previewSummary.sample_ips.length > 0 ? (
                        <div className="flex flex-wrap gap-1 pt-0.5">
                          {previewSummary.sample_ips.slice(0, 8).map((ip) => (
                            <Badge key={ip} variant="secondary" className="font-mono text-[10px]">
                              {ip}
                            </Badge>
                          ))}
                          {previewSummary.matched_hosts_count > 8 && (
                            <Badge variant="outline" className="font-mono text-[10px]">
                              +{previewSummary.matched_hosts_count - 8} więcej
                            </Badge>
                          )}
                        </div>
                      ) : (
                        <p className="text-[11px] text-muted-foreground">
                          Brak pasujących odkrytych hostów w bazie — konto nie zobaczy żadnych hostów, dopóki nie przypiszesz grupy, IP/CIDR lub hostów poniżej.
                        </p>
                      )}
                    </div>

                    {/* 2a. Przypisane grupy */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 font-medium text-foreground">
                          <Layers className="h-3.5 w-3.5 text-muted-foreground" />
                          <span>Przypisane grupy ({scope.group_ids.length})</span>
                        </div>
                        {scope.group_ids.length > 0 && (
                          <button
                            type="button"
                            onClick={() => setScope((p) => ({ ...p, group_ids: [] }))}
                            className="text-[11px] underline text-muted-foreground hover:text-foreground"
                          >
                            Odznacz grupy
                          </button>
                        )}
                      </div>

                      {availableGroups.length > 4 && (
                        <div className="relative">
                          <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
                          <Input
                            value={groupSearch}
                            onChange={(e) => setGroupSearch(e.target.value)}
                            placeholder="Filtruj grupy..."
                            className="pl-8 h-7 text-xs"
                          />
                        </div>
                      )}

                      <div className="max-h-36 overflow-y-auto divide-y divide-border/60 rounded-md border border-border bg-background">
                        {filteredGroups.map((grp) => {
                          const checked = scope.group_ids.includes(grp.id);
                          return (
                            <label
                              key={grp.id}
                              className="flex items-center justify-between gap-2 px-2.5 py-2 hover:bg-muted/40 cursor-pointer"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <Checkbox
                                  checked={checked}
                                  onCheckedChange={() => toggleGroupId(grp.id)}
                                />
                                <Badge
                                  variant={grp.group_type === 'dynamic' ? 'default' : 'secondary'}
                                  className="font-mono text-[9px] px-1 py-0 shrink-0"
                                >
                                  {grp.group_type === 'dynamic' ? 'AUTO' : 'STATIC'}
                                </Badge>
                                <span className="font-medium text-foreground truncate">{grp.name}</span>
                              </div>
                              <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                                {grp.member_count} {grp.group_type === 'dynamic' ? 'hostów' : 'celów'}
                              </span>
                            </label>
                          );
                        })}
                        {!loadingCatalog && filteredGroups.length === 0 && (
                          <div className="py-3 text-center text-[11px] text-muted-foreground">
                            Brak zapisanych grup. Utwórz Smart Group w zakładce Groups lub użyj pól IP/CIDR poniżej.
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 2b. Pojedyncze IP, podsieci CIDR i zakresy start-koniec */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 font-medium text-foreground">
                          <Network className="h-3.5 w-3.5 text-muted-foreground" />
                          <span>IP, podsieci CIDR i zakresy IP ({totalNetEntries})</span>
                        </div>
                        {totalNetEntries > 0 && (
                          <button
                            type="button"
                            onClick={() =>
                              setScope((p) => ({ ...p, ips: [], cidrs: [], ip_ranges: [] }))
                            }
                            className="text-[11px] underline text-muted-foreground hover:text-foreground"
                          >
                            Wyczyść wszystkie
                          </button>
                        )}
                      </div>

                      <div className="flex gap-2">
                        <Input
                          value={networkInput}
                          onChange={(e) => setNetworkInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              e.preventDefault();
                              handleAddNetworkTokens();
                            }
                          }}
                          placeholder="np. 172.28.0.10, 172.28.0.0/28 lub 172.28.0.10-172.28.0.20"
                          className="flex-1 font-mono h-8 text-xs"
                        />
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={handleAddNetworkTokens}
                          className="h-8"
                        >
                          <Plus className="h-3.5 w-3.5" />
                          Dodaj
                        </Button>
                      </div>

                      {totalNetEntries > 0 ? (
                        <div className="flex flex-wrap gap-1.5 rounded-md border border-border bg-muted/20 p-2">
                          {scope.ips.map((ip) => (
                            <Badge key={`ip:${ip}`} variant="secondary" className="font-mono text-[10px] gap-1 pr-1">
                              <span className="text-muted-foreground">IP</span> {ip}
                              <button
                                type="button"
                                onClick={() => removeScopeToken('ips', ip)}
                                className="hover:text-foreground text-muted-foreground"
                                title={`Usuń ${ip}`}
                              >
                                <X className="h-2.5 w-2.5" />
                              </button>
                            </Badge>
                          ))}
                          {scope.cidrs.map((cidr) => (
                            <Badge key={`cidr:${cidr}`} variant="default" className="font-mono text-[10px] gap-1 pr-1">
                              CIDR {cidr}
                              <button
                                type="button"
                                onClick={() => removeScopeToken('cidrs', cidr)}
                                className="opacity-80 hover:opacity-100"
                                title={`Usuń ${cidr}`}
                              >
                                <X className="h-2.5 w-2.5" />
                              </button>
                            </Badge>
                          ))}
                          {scope.ip_ranges.map((rng) => (
                            <Badge key={`rng:${rng}`} variant="outline" className="font-mono text-[10px] gap-1 pr-1">
                              <span className="text-muted-foreground">ZAKRES</span> {rng}
                              <button
                                type="button"
                                onClick={() => removeScopeToken('ip_ranges', rng)}
                                className="hover:text-foreground text-muted-foreground"
                                title={`Usuń ${rng}`}
                              >
                                <X className="h-2.5 w-2.5" />
                              </button>
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[11px] text-muted-foreground">
                          Możesz wkleić wiele wpisów oddzielonych przecinkami (pojedyncze IP, CIDR <code className="font-mono">/28</code> lub zakres <code className="font-mono">start-koniec</code>).
                        </p>
                      )}
                    </div>

                    {/* 2c. Wyklikanie konkretnych odkrytych hostów */}
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 font-medium text-foreground">
                          <Server className="h-3.5 w-3.5 text-muted-foreground" />
                          <span>Konkretne odkryte hosty ({scope.host_ids.length} wybranych)</span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px]">
                          {filteredHosts.length > 0 && (
                            <button
                              type="button"
                              onClick={selectAllFilteredHosts}
                              className="underline text-muted-foreground hover:text-foreground"
                            >
                              Zaznacz widoczne ({filteredHosts.length})
                            </button>
                          )}
                          {scope.host_ids.length > 0 && (
                            <button
                              type="button"
                              onClick={clearSelectedHosts}
                              className="underline text-muted-foreground hover:text-foreground"
                            >
                              Wyczyść
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="relative">
                        <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
                        <Input
                          value={hostSearch}
                          onChange={(e) => setHostSearch(e.target.value)}
                          placeholder="Szukaj hosta po IP, nazwie, jednostce lub technologii..."
                          className="pl-8 h-7 text-xs"
                        />
                      </div>

                      <div className="max-h-44 overflow-y-auto divide-y divide-border/60 rounded-md border border-border bg-background">
                        {filteredHosts.map((h) => {
                          const checked = scope.host_ids.includes(h.id);
                          return (
                            <label
                              key={h.id}
                              className="flex items-center justify-between gap-2 px-2.5 py-1.5 hover:bg-muted/40 cursor-pointer"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <Checkbox
                                  checked={checked}
                                  onCheckedChange={() => toggleHostId(h.id)}
                                />
                                <span className="font-mono font-medium text-foreground shrink-0">
                                  {h.ip_address}
                                </span>
                                {(h.override?.custom_label || h.hostname) && (
                                  <span className="text-[11px] text-muted-foreground truncate">
                                    {h.override?.custom_label || h.hostname}
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-1.5 shrink-0">
                                {(h.technologies || []).slice(0, 2).map((t) => (
                                  <Badge key={t} variant="outline" className="font-mono text-[9px] px-1 py-0">
                                    {t}
                                  </Badge>
                                ))}
                                <Badge variant="secondary" className="font-mono text-[9px] px-1 py-0">
                                  {h.status}
                                </Badge>
                              </div>
                            </label>
                          );
                        })}
                        {!loadingCatalog && filteredHosts.length === 0 && (
                          <div className="py-3 text-center text-[11px] text-muted-foreground">
                            Brak hostów pasujących do filtra.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Stopka z akcjami */}
            <div className="pt-3 border-t border-border/60 flex items-center justify-between gap-2 shrink-0">
              <div>
                {!isSelf && (
                  <Button
                    type="button"
                    variant={confirmDelete ? 'default' : 'ghost'}
                    size="sm"
                    disabled={deleting || saving}
                    onClick={handleDelete}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    {deleting ? 'Usuwanie...' : confirmDelete ? 'Potwierdź usunięcie' : 'Usuń konto'}
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2">
                <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)}>
                  Anuluj
                </Button>
                <Button type="submit" size="sm" disabled={saving || Boolean(scopeRestricted && previewError)}>
                  <Save className="h-3.5 w-3.5" />
                  {saving ? 'Zapisywanie...' : 'Zapisz ustawienia'}
                </Button>
              </div>
            </div>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}
