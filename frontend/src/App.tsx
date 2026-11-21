import { AlertCircle, KeyRound, LogOut, Moon, RefreshCw, Sun } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { API_BASE, apiFetch, setAuthToken, syncDynamicRoles } from './api';
import { ChangesTab } from './components/ChangesTab';
import { DashboardTab } from './components/DashboardTab';
import { DefectDojoTab } from './components/DefectDojoTab';
import { HostsTab } from './components/HostsTab';
import { RbacAuditTab } from './components/RbacAuditTab';
import { SignaturesTab } from './components/SignaturesTab';
import { TargetsScansTab } from './components/TargetsScansTab';
import { Alert, AlertDescription } from './components/ui/alert';
import { Badge } from './components/ui/badge';
import { Button } from './components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { Input } from './components/ui/input';
import { Select } from './components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import type {
  AuthSession,
  ChangeEvent,
  DashboardSummary,
  HealthResponse,
  HostSummary,
  RoleItem,
  UserRole,
} from './types';

type TabKey = 'dashboard' | 'hosts' | 'changes' | 'targets' | 'signatures' | 'defectdojo' | 'rbac';
type ThemeMode = 'dark' | 'light';

const TABS: { key: TabKey; label: string }[] = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'hosts', label: 'Hosts' },
  { key: 'changes', label: 'Diff' },
  { key: 'targets', label: 'Targets & Scans' },
  { key: 'signatures', label: 'Signatures' },
  { key: 'defectdojo', label: 'DefectDojo' },
  { key: 'rbac', label: 'RBAC & Audit' },
];

const DEFAULT_ROLES: UserRole[] = ['admin', 'add_delete_modify', 'modify_read', 'read_only'];

export default function App() {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('asi-theme');
      return saved === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });
  const [role, setRole] = useState<UserRole>('admin');
  const [availableRoles, setAvailableRoles] = useState<UserRole[]>(DEFAULT_ROLES);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('admin123!');
  const [loginErr, setLoginErr] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);

  const [activeTab, setActiveTab] = useState<TabKey>('dashboard');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [changes, setChanges] = useState<ChangeEvent[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    try {
      localStorage.setItem('asi-theme', theme);
    } catch {
      // ignore storage errors
    }
  }, [theme]);

  const effectiveRole = session ? session.role : role;

  const refreshRoles = useCallback(async () => {
    try {
      const rolesData = await apiFetch<RoleItem[]>('/rbac/roles', effectiveRole);
      syncDynamicRoles(rolesData);
      const names = rolesData.map((r) => r.name);
      if (names.length > 0) setAvailableRoles(names);
    } catch {
      // keep default roles
    }
  }, [effectiveRole]);

  const refreshCoreData = useCallback(async () => {
    try {
      const [hRes, hostsRes, changesRes, sumRes] = await Promise.all([
        apiFetch<HealthResponse>('/health', effectiveRole),
        apiFetch<HostSummary[]>('/hosts?limit=200', effectiveRole),
        apiFetch<ChangeEvent[]>('/changes?limit=200', effectiveRole),
        apiFetch<DashboardSummary>('/dashboard/summary', effectiveRole),
      ]);
      setHealth(hRes);
      setHosts(hostsRes);
      setChanges(changesRes);
      setSummary(sumRes);
      setApiError(null);
    } catch (e) {
      setApiError(e instanceof Error ? e.message : 'Brak połączenia z Backend API');
    }
  }, [effectiveRole]);

  useEffect(() => {
    refreshRoles();
    refreshCoreData();
  }, [refreshRoles, refreshCoreData]);

  async function handleJwtLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoggingIn(true);
    setLoginErr(null);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUser.trim(), password: loginPass }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setAuthToken(data.access_token);
      setSession({
        token: data.access_token,
        username: data.username,
        role: data.role,
        permissions: data.permissions || [],
      });
      setRole(data.role);
      setShowLogin(false);
    } catch (err) {
      setLoginErr(err instanceof Error ? err.message : 'Błąd logowania JWT');
    } finally {
      setLoggingIn(false);
    }
  }

  function handleLogout() {
    setAuthToken(null);
    setSession(null);
  }

  return (
    <Tabs
      value={activeTab}
      onValueChange={(v) => setActiveTab(v as TabKey)}
      className="min-h-screen bg-background text-foreground transition-colors"
    >
      {/* Kompaktowy jednoliniowy pasek górny */}
      <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-12 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 overflow-x-auto">
            <span className="px-2 py-0.5 rounded bg-primary text-primary-foreground font-mono font-bold text-xs tracking-tight shrink-0">
              Janus ASI
            </span>
            <TabsList className="h-8 bg-transparent border-0 p-0 gap-0.5">
              {TABS.map((tab) => (
                <TabsTrigger
                  key={tab.key}
                  value={tab.key}
                  className="h-7 px-2.5 text-xs data-[state=active]:bg-secondary data-[state=active]:border-border"
                >
                  {tab.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Badge variant={apiError ? 'outline' : 'secondary'} className="font-mono hidden lg:inline-flex">
              {apiError
                ? 'OFFLINE'
                : health
                ? `${health.status.toUpperCase()} • DB:${health.services.postgres} • R:${health.services.redis}`
                : '...'}
            </Badge>

            {session ? (
              <div className="flex items-center gap-1.5">
                <Badge variant="default" className="font-mono text-[11px]">
                  JWT: {session.username} ({session.role})
                </Badge>
                <Button variant="outline" size="icon" onClick={handleLogout} title="Wyloguj JWT (wróć do przełącznika demo)">
                  <LogOut className="h-3.5 w-3.5" />
                </Button>
              </div>
            ) : (
              <>
                <div className="w-40">
                  <Select
                    value={role}
                    onChange={(e) => setRole(e.target.value as UserRole)}
                    className="h-8 font-mono text-xs"
                    aria-label="Rola RBAC"
                  >
                    {availableRoles.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </Select>
                </div>
                <Button
                  variant={showLogin ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setShowLogin((v) => !v)}
                  className="h-8 px-2 text-xs font-mono"
                  title="Zaloguj przez JWT"
                >
                  <KeyRound className="h-3.5 w-3.5" />
                  JWT
                </Button>
              </>
            )}

            <Button
              variant="outline"
              size="icon"
              onClick={() => setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))}
              title={theme === 'dark' ? 'Tryb jasny' : 'Tryb ciemny'}
              aria-label="Przełącz motyw"
            >
              {theme === 'dark' ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
            </Button>

            <Button variant="outline" size="icon" onClick={refreshCoreData} title="Odśwież" aria-label="Odśwież">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-5">
        {showLogin && !session && (
          <Card className="mb-4">
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center justify-between">
                <span>Logowanie JWT (Bearer Token — konta z tabeli users)</span>
                <div className="flex gap-1.5 text-[11px] font-mono">
                  {(
                    [
                      ['admin', 'admin123!'],
                      ['operator', 'operator123!'],
                      ['analyst', 'analyst123!'],
                      ['viewer', 'viewer123!'],
                    ] as const
                  ).map(([u, p]) => (
                    <Button
                      key={u}
                      type="button"
                      size="sm"
                      variant="outline"
                      className="h-6 px-2 text-[10px]"
                      onClick={() => {
                        setLoginUser(u);
                        setLoginPass(p);
                      }}
                    >
                      {u}
                    </Button>
                  ))}
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="pb-4">
              {loginErr && (
                <Alert variant="destructive" className="mb-3">
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                  <AlertDescription className="text-foreground">{loginErr}</AlertDescription>
                </Alert>
              )}
              <form onSubmit={handleJwtLogin} className="flex flex-wrap items-center gap-2 text-xs">
                <Input
                  required
                  value={loginUser}
                  onChange={(e) => setLoginUser(e.target.value)}
                  placeholder="Nazwa użytkownika"
                  className="w-44 font-mono"
                />
                <Input
                  required
                  type="password"
                  value={loginPass}
                  onChange={(e) => setLoginPass(e.target.value)}
                  placeholder="Hasło"
                  className="w-44 font-mono"
                />
                <Button type="submit" size="sm" disabled={loggingIn}>
                  {loggingIn ? 'Logowanie...' : 'Zaloguj JWT'}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {apiError && (
          <Alert variant="destructive" className="mb-4">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <AlertDescription className="text-foreground">{apiError}</AlertDescription>
          </Alert>
        )}

        <TabsContent value="dashboard" className="mt-0">
          <DashboardTab
            role={effectiveRole}
            hosts={hosts}
            changes={changes}
            summary={summary}
            onRefresh={refreshCoreData}
          />
        </TabsContent>
        <TabsContent value="hosts" className="mt-0">
          <HostsTab role={effectiveRole} hosts={hosts} onRefresh={refreshCoreData} />
        </TabsContent>
        <TabsContent value="changes" className="mt-0">
          <ChangesTab role={effectiveRole} changes={changes} onRefresh={refreshCoreData} />
        </TabsContent>
        <TabsContent value="targets" className="mt-0">
          <TargetsScansTab role={effectiveRole} onRefreshAll={refreshCoreData} />
        </TabsContent>
        <TabsContent value="signatures" className="mt-0">
          <SignaturesTab role={effectiveRole} />
        </TabsContent>
        <TabsContent value="defectdojo" className="mt-0">
          <DefectDojoTab role={effectiveRole} hosts={hosts} />
        </TabsContent>
        <TabsContent value="rbac" className="mt-0">
          <RbacAuditTab role={effectiveRole} onRolesChanged={refreshRoles} />
        </TabsContent>
      </main>
    </Tabs>
  );
}
