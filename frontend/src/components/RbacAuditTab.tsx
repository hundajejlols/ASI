import { AlertCircle, CheckCircle2, Edit3, Lock, Plus, Shield, Trash2, Users } from 'lucide-react';
import { useEffect, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type { AuditLogItem, RoleItem, UserItem, UserRole } from '../types';
import { formatTime } from './Badges';
import { UserEditSheet } from './UserEditSheet';
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
  currentUsername?: string | null;
  isCurrentUserScoped?: boolean;
  onRolesChanged: () => void;
}

const ALL_PERMS = ['read', 'modify', 'add', 'delete', 'manage_integrations', 'manage_users'] as const;

export function RbacAuditTab({ role, currentUsername = null, isCurrentUserScoped = false, onRolesChanged }: Props) {
  const [roles, setRoles] = useState<RoleItem[]>([]);
  const [users, setUsers] = useState<UserItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Nowa własna rola RBAC
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [newRolePerms, setNewRolePerms] = useState<string[]>(['read']);
  const [savingRole, setSavingRole] = useState(false);

  // Nowy użytkownik
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('read_only');
  const [openScopeAfterCreate, setOpenScopeAfterCreate] = useState(false);
  const [savingUser, setSavingUser] = useState(false);

  // Edycja konta i zakresu widoczności
  const [editingUser, setEditingUser] = useState<UserItem | null>(null);
  const [editSheetOpen, setEditSheetOpen] = useState(false);

  const canManageUsers = hasPermission(role, 'manage_users');
  const canEditAccounts = canManageUsers && !isCurrentUserScoped;

  async function loadAll() {
    setError(null);
    try {
      const rolesRes = await apiFetch<RoleItem[]>('/rbac/roles', role);
      setRoles(rolesRes);
      if (canManageUsers) {
        const [usersRes, logsRes] = await Promise.all([
          apiFetch<UserItem[]>('/rbac/users', role),
          apiFetch<AuditLogItem[]>('/audit-logs?limit=50', role),
        ]);
        setUsers(usersRes);
        setAuditLogs(logsRes);
      } else {
        setUsers([]);
        setAuditLogs([]);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Błąd ładowania danych RBAC / audytu');
    }
  }

  useEffect(() => {
    loadAll();
  }, [role]);

  function togglePerm(perm: string, checked: boolean) {
    setNewRolePerms((prev) =>
      checked ? (prev.includes(perm) ? prev : [...prev, perm]) : prev.filter((p) => p !== perm)
    );
  }

  async function handleCreateRole(e: React.FormEvent) {
    e.preventDefault();
    if (!canManageUsers || !newRoleName.trim()) return;
    setSavingRole(true);
    setError(null);
    setNotice(null);
    try {
      await apiFetch('/rbac/roles', role, {
        method: 'POST',
        body: JSON.stringify({
          name: newRoleName.trim().toLowerCase(),
          description: newRoleDesc.trim() || null,
          permissions: newRolePerms,
        }),
      });
      setNotice(`Utworzono własną rolę RBAC '${newRoleName.trim().toLowerCase()}'.`);
      setNewRoleName('');
      setNewRoleDesc('');
      setNewRolePerms(['read']);
      await loadAll();
      onRolesChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd tworzenia roli');
    } finally {
      setSavingRole(false);
    }
  }

  async function handleDeleteRole(name: string) {
    if (!canManageUsers) return;
    setError(null);
    setNotice(null);
    try {
      await apiFetch(`/rbac/roles/${name}`, role, { method: 'DELETE' });
      setNotice(`Usunięto rolę '${name}'.`);
      await loadAll();
      onRolesChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd usuwania roli');
    }
  }

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    if (!canEditAccounts || !newUsername.trim() || !newEmail.trim() || !newPassword) return;
    setSavingUser(true);
    setError(null);
    setNotice(null);
    try {
      const created = await apiFetch<UserItem>('/rbac/users', role, {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          email: newEmail.trim(),
          password: newPassword,
          role_name: newUserRole,
          scope_restricted: openScopeAfterCreate,
        }),
      });
      setNotice(`Dodano użytkownika '${created.username}' (rola: ${created.role}).`);
      setNewUsername('');
      setNewEmail('');
      setNewPassword('');
      await loadAll();
      if (openScopeAfterCreate) {
        setEditingUser(created);
        setEditSheetOpen(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Błąd tworzenia użytkownika');
    } finally {
      setSavingUser(false);
    }
  }

  function renderScopeCell(u: UserItem) {
    if (!u.scope_restricted) {
      return (
        <Badge variant="outline" className="font-mono text-[10px]">
          Pełny dostęp
        </Badge>
      );
    }
    const sum = u.scope_summary;
    const parts: string[] = [];
    if (sum?.group_ids_count) parts.push(`${sum.group_ids_count} gr.`);
    if (sum?.cidrs_count) parts.push(`${sum.cidrs_count} CIDR`);
    if (sum?.ip_ranges_count) parts.push(`${sum.ip_ranges_count} zakr.`);
    if (sum?.ips_count) parts.push(`${sum.ips_count} IP`);
    if (sum?.host_ids_count) parts.push(`${sum.host_ids_count} host.`);

    return (
      <div className="space-y-0.5">
        <Badge variant="default" className="font-mono text-[10px] gap-1">
          <Lock className="h-2.5 w-2.5" />
          {sum ? `${sum.matched_hosts_count} hostów` : 'Ograniczony'}
        </Badge>
        {parts.length > 0 && (
          <div className="font-mono text-[10px] text-muted-foreground">{parts.join(' · ')}</div>
        )}
      </div>
    );
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
        {/* Role RBAC (wbudowane + tworzenie własnych) */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-muted-foreground" />
              Role RBAC ({roles.length}) — Tworzenie i uprawnienia
            </CardTitle>
            <CardDescription>
              4 role wymagane przez CBI AGH + możliwość tworzenia własnych ról przez administratora.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {canManageUsers && (
              <form onSubmit={handleCreateRole} className="space-y-3 p-3 rounded-md border border-border bg-muted/30 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <Input
                    required
                    value={newRoleName}
                    onChange={(e) => setNewRoleName(e.target.value)}
                    placeholder="Nazwa roli np. soc_auditor"
                    className="font-mono"
                  />
                  <Input
                    value={newRoleDesc}
                    onChange={(e) => setNewRoleDesc(e.target.value)}
                    placeholder="Opis roli (opcjonalnie)"
                  />
                </div>
                <div className="flex flex-wrap gap-3">
                  {ALL_PERMS.map((p) => (
                    <label key={p} className="flex items-center gap-1.5 cursor-pointer">
                      <Checkbox
                        checked={newRolePerms.includes(p)}
                        onCheckedChange={(v) => togglePerm(p, Boolean(v))}
                      />
                      <span className="font-mono">{p}</span>
                    </label>
                  ))}
                </div>
                <Button type="submit" size="sm" disabled={savingRole || newRolePerms.length === 0}>
                  <Plus className="h-3.5 w-3.5" />
                  {savingRole ? 'Tworzenie...' : 'Utwórz własną rolę'}
                </Button>
              </form>
            )}

            <div className="rounded-md border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rola</TableHead>
                    <TableHead>Uprawnienia</TableHead>
                    {canManageUsers && <TableHead className="text-right">Akcja</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {roles.map((r) => (
                    <TableRow key={r.name}>
                      <TableCell>
                        <div className="font-mono font-semibold text-foreground">{r.name}</div>
                        {r.description && <div className="text-[11px] text-muted-foreground">{r.description}</div>}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {r.permissions.map((p) => (
                            <Badge key={p} variant="secondary" className="font-mono text-[10px]">
                              {p}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      {canManageUsers && (
                        <TableCell className="text-right">
                          {!r.is_system ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDeleteRole(r.name)}
                              className="h-7 px-2"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          ) : (
                            <Badge variant="outline" className="font-mono text-[10px]">system</Badge>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Użytkownicy JWT */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Users className="h-4 w-4 text-muted-foreground" />
              Użytkownicy JWT ({users.length}) &amp; Ograniczenia widoczności
            </CardTitle>
            <CardDescription>
              Kliknij <strong>Edytuj</strong> przy koncie, aby przypisać grupy, konkretne IP, podsieci CIDR lub zakresy IP widoczne dla użytkownika.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {canManageUsers ? (
              <>
                {canEditAccounts ? (
                  <form onSubmit={handleCreateUser} className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 p-3 rounded-md border border-border bg-muted/30 text-xs">
                    <Input
                      required
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      placeholder="Login np. jkowalski"
                      className="font-mono"
                    />
                    <Input
                      required
                      type="email"
                      value={newEmail}
                      onChange={(e) => setNewEmail(e.target.value)}
                      placeholder="jkowalski@agh.edu.pl"
                    />
                    <Input
                      required
                      type="password"
                      minLength={6}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Hasło (min. 6 zn.)"
                    />
                    <Select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value)}>
                      {roles.map((r) => (
                        <option key={r.name} value={r.name}>
                          {r.name}
                        </option>
                      ))}
                    </Select>
                    <label className="sm:col-span-2 flex items-center gap-2 cursor-pointer text-muted-foreground">
                      <Checkbox
                        checked={openScopeAfterCreate}
                        onCheckedChange={(v) => setOpenScopeAfterCreate(Boolean(v))}
                      />
                      <span>Ogranicz widoczność i otwórz od razu ustawienia zakresu po utworzeniu konta</span>
                    </label>
                    <div className="sm:col-span-2">
                      <Button type="submit" size="sm" disabled={savingUser}>
                        <Plus className="h-3.5 w-3.5" />
                        {savingUser ? 'Dodawanie...' : 'Dodaj użytkownika'}
                      </Button>
                    </div>
                  </form>
                ) : (
                  <p className="text-xs text-muted-foreground rounded-md border border-border bg-muted/20 px-3 py-2">
                    To konto ma ograniczony zakres widoczności — tworzenie kont i zmiana zakresów wymaga administratora z pełnym dostępem.
                  </p>
                )}

                <div className="rounded-md border border-border overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Użytkownik</TableHead>
                        <TableHead>Rola</TableHead>
                        <TableHead>Widoczność</TableHead>
                        {canEditAccounts && <TableHead className="text-right">Akcja</TableHead>}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {users.map((u) => (
                        <TableRow key={u.id} className={!u.is_active ? 'opacity-60' : undefined}>
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono font-medium text-foreground">{u.username}</span>
                              {!u.is_active && (
                                <Badge variant="outline" className="font-mono text-[9px] px-1 py-0">
                                  zablokowane
                                </Badge>
                              )}
                            </div>
                            <div className="text-[11px] text-muted-foreground">{u.email}</div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary" className="font-mono text-[10px]">
                              {u.role}
                            </Badge>
                          </TableCell>
                          <TableCell>{renderScopeCell(u)}</TableCell>
                          {canEditAccounts && (
                            <TableCell className="text-right">
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                  setEditingUser(u);
                                  setEditSheetOpen(true);
                                }}
                                className="h-7 px-2.5 text-xs"
                              >
                                <Edit3 className="h-3 w-3" />
                                Edytuj
                              </Button>
                            </TableCell>
                          )}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            ) : (
              <p className="text-xs text-muted-foreground">
                Zarządzanie użytkownikami i podgląd dziennika audytu wymagają roli <code className="font-mono">admin</code>.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Dziennik audytu (audit_logs) */}
      {canManageUsers && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Dziennik audytu operacji (audit_logs — ostatnie {auditLogs.length})</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Czas</TableHead>
                  <TableHead>Akcja</TableHead>
                  <TableHead>Zasób</TableHead>
                  <TableHead>Szczegóły</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditLogs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                      {formatTime(log.created_at)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-[10px]">{log.action}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {log.resource_type}{log.resource_id ? ` (${log.resource_id.slice(0, 18)})` : ''}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground max-w-md truncate">
                      {JSON.stringify(log.details)}
                    </TableCell>
                  </TableRow>
                ))}
                {auditLogs.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">
                      Brak wpisów audytowych.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <UserEditSheet
        open={editSheetOpen}
        onOpenChange={setEditSheetOpen}
        user={editingUser}
        role={role}
        roles={roles}
        currentUsername={currentUsername}
        onSaved={(updated) => {
          setNotice(
            updated.scope_restricted
              ? `Zapisano ustawienia konta '${updated.username}' (ograniczony zakres: ${updated.scope_summary?.matched_hosts_count ?? 0} odkrytych hostów).`
              : `Zapisano ustawienia konta '${updated.username}' (pełny dostęp).`
          );
          loadAll();
        }}
        onDeleted={(_id, uname) => {
          setNotice(`Usunięto konto użytkownika '${uname}'.`);
          loadAll();
        }}
      />
    </div>
  );
}
