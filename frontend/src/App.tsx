import {
  AlertCircle,
  Bug,
  Fingerprint,
  KeyRound,
  Lock,
  LogOut,
  Moon,
  RefreshCw,
  Sparkles,
  Sun,
  UserCog,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { API_BASE, apiFetch, setAuthToken, syncDynamicRoles } from './api';
import { AiAgentTab } from './components/AiAgentTab';
import { ChangesTab } from './components/ChangesTab';
import { DashboardTab } from './components/DashboardTab';
import { DefectDojoTab } from './components/DefectDojoTab';
import { GroupsTab } from './components/GroupsTab';
import { HostDetailSheet } from './components/HostDetailSheet';
import { HostsTab } from './components/HostsTab';
import { NotificationBell } from './components/NotificationBell';
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
  SignatureDraft,
  UserRole,
} from './types';

type TabKey =
  | 'dashboard'
  | 'hosts'
  | 'groups'
  | 'changes'
  | 'targets'
  | 'signatures'
  | 'ai_agent'
  | 'defectdojo'
  | 'rbac';
type ThemeMode = 'dark' | 'light';

const PRIMARY_TABS: { key: TabKey; label: string; title: string }[] = [
  { key: 'dashboard', label: 'Dashboard', title: 'Przegląd i statystyki powierzchni ataku' },
  { key: 'hosts', label: 'Hosts', title: 'Odkryte hosty i usługi' },
  { key: 'groups', label: 'Groups', title: 'Automatyczne grupy i Smart Groups' },
  { key: 'changes', label: 'Diff', title: 'Historia zmian (Diff)' },
  { key: 'targets', label: 'Scans', title: 'Cele, skanowanie i harmonogramy' },
];

const ICON_TABS: {
  key: TabKey;
  label: string;
  title: string;
  Icon: typeof Fingerprint;
}[] = [
  { key: 'signatures', label: 'Signatures', title: 'Sygnatury pasywne (kreator, import/eksport JSON)', Icon: Fingerprint },
  { key: 'defectdojo', label: 'DefectDojo', title: 'Integracja DefectDojo (1 IP = 1 Asset)', Icon: Bug },
  { key: 'rbac', label: 'RBAC', title: 'Role RBAC, Konta, Zakres widoczności i Audyt', Icon: UserCog },
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
  const [signatureDraft, setSignatureDraft] = useState<SignatureDraft | null>(null);
  const [groupSearchQuery, setGroupSearchQuery] = useState<string | null>(null);
  const [ddPreselect, setDdPreselect] = useState<{ hostIds: string[]; label: string } | null>(null);
  const [bellHostId, setBellHostId] = useState<string | null>(null);
  const [alertsVersion, setAlertsVersion] = useState(0);
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
  const authKey = session ? `jwt:${session.username}:${session.token.slice(-10)}` : `demo:${role}`;

  const refreshRoles = useCallback(async () => {
    try {
      const rolesData = await apiFetch<RoleItem[]>('/rbac/roles', effectiveRole);
      syncDynamicRoles(rolesData);
      const names = rolesData.map((r) => r.name);
      if (names.length > 0) setAvailableRoles(names);
    } catch {
      // keep default roles
    }
  }, [effectiveRole, authKey]);

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
  }, [effectiveRole, authKey]);

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
        scope_restricted: Boolean(data.scope_restricted),
        scope_summary: data.scope_summary ?? null,
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

  const handleCreateSignatureFromHost = useCallback((draft: SignatureDraft) => {
    setSignatureDraft(draft);
    setActiveTab('signatures');
  }, []);

  const handleSignatureDraftConsumed = useCallback(() => {
    setSignatureDraft(null);
  }, []);

  const handleOpenGroupSearch = useCallback((query: string) => {
    setGroupSearchQuery(query);
    setActiveTab('groups');
  }, []);

  const handleGroupSearchConsumed = useCallback(() => {
    setGroupSearchQuery(null);
  }, []);

  const handleExportGroupToDefectDojo = useCallback((hostIds: string[], label: string) => {
    setDdPreselect({ hostIds, label });
    setActiveTab('defectdojo');
  }, []);

  const bumpAlertsVersion = useCallback(() => {
    setAlertsVersion((v) => v + 1);
  }, []);

  const handleCloseBellHost = useCallback(() => {
    setBellHostId(null);
  }, []);

  const handleDdPreselectConsumed = useCallback(() => {
    setDdPreselect(null);
  }, []);

  return (
    <Tabs
      value={activeTab}
      onValueChange={(v) => setActiveTab(v as TabKey)}
      className="min-h-screen bg-background text-foreground transition-colors"
    >
      {/* Kompaktowy, uporządkowany pasek górny */}
      <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-12 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0 overflow-x-auto">
            <button
              type="button"
              onClick={() => setActiveTab('dashboard')}
              className="px-2 py-0.5 rounded bg-primary text-primary-foreground font-mono font-bold text-xs tracking-tight shrink-0 hover:opacity-90 transition-opacity"
              title="Przejdź do Dashboardu"
            >
              Janus ASI
            </button>

            <TabsList className="h-8 bg-transparent border-0 p-0 gap-0.5">
              {PRIMARY_TABS.map((tab) => (
                <TabsTrigger
                  key={tab.key}
                  value={tab.key}
                  title={tab.title}
                  className="h-7 px-2.5 text-xs data-[state=active]:bg-secondary data-[state=active]:border-border"
                >
                  {tab.label}
                </TabsTrigger>
              ))}

              <span className="mx-1 h-4 w-px bg-border shrink-0" aria-hidden="true" />

              {ICON_TABS.map(({ key, label, title, Icon }) => {
                const isActive = activeTab === key;
                return (
                  <TabsTrigger
                    key={key}
                    value={key}
                    title={title}
                    aria-label={title}
                    className={`h-7 text-xs gap-1.5 data-[state=active]:bg-secondary data-[state=active]:border-border ${
                      isActive ? 'px-2.5' : 'px-2'
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5 shrink-0" />
                    {isActive && <span>{label}</span>}
                  </TabsTrigger>
                );
              })}
            </TabsList>
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            {/* Kompaktowa kropka statusu API/DB/Redis zamiast szerokiego badge */}
            <span
              className="hidden sm:inline-flex items-center justify-center h-8 px-2 rounded-md border border-border bg-secondary/40 gap-1.5 font-mono text-[10px] text-muted-foreground"
              title={
                apiError
                  ? 'Backend API: OFFLINE'
                  : health
                  ? `API: ${health.status.toUpperCase()} • PostgreSQL: ${health.services.postgres} • Redis: ${health.services.redis}`
                  : 'Łączenie z Backend API...'
              }
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  apiError
                    ? 'bg-red-500'
                    : health?.status === 'ok'
                    ? 'bg-emerald-500'
                    : 'bg-amber-400 animate-pulse'
                }`}
              />
              <span className="hidden xl:inline">{apiError ? 'OFFLINE' : 'OK'}</span>
            </span>

            {session ? (
              <div className="flex items-center gap-1.5">
                <Badge variant="default" className="font-mono text-[11px]">
                  {session.username} ({session.role})
                </Badge>
                {session.scope_restricted && (
                  <Badge
                    variant="outline"
                    className="font-mono text-[10px] gap-1"
                    title="Konto ma ograniczony zakres widoczności zasobów"
                  >
                    <Lock className="h-2.5 w-2.5" />
                    {session.scope_summary?.matched_hosts_count ?? 0} hostów
                  </Badge>
                )}
                <Button variant="outline" size="icon" onClick={handleLogout} title="Wyloguj JWT (wróć do przełącznika demo)">
                  <LogOut className="h-3.5 w-3.5" />
                </Button>
              </div>
            ) : (
              <>
                <div className="w-32">
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

            <span className="mx-0.5 h-4 w-px bg-border shrink-0" aria-hidden="true" />

            {/* Lekko świecąca ikona AI Security Agenta po prawej stronie */}
            <button
              type="button"
              onClick={() => setActiveTab('ai_agent')}
              title="AI Security Agent (OpenRouter — pasywna analiza podatności)"
              aria-label="AI Security Agent"
              className={`relative inline-flex h-8 items-center justify-center gap-1.5 rounded-md border transition-all duration-300 ${
                activeTab === 'ai_agent'
                  ? 'px-2.5 border-violet-400/80 bg-violet-500/20 text-violet-700 dark:text-violet-200 shadow-[0_0_16px_rgba(167,139,250,0.55)]'
                  : 'w-8 border-violet-400/45 bg-violet-500/10 text-violet-600 dark:text-violet-300 shadow-[0_0_12px_rgba(167,139,250,0.38)] hover:shadow-[0_0_18px_rgba(167,139,250,0.65)] hover:border-violet-400/75'
              }`}
            >
              <span
                className="pointer-events-none absolute inset-0 rounded-md bg-violet-400/15 animate-pulse"
                aria-hidden="true"
              />
              <Sparkles className="relative h-3.5 w-3.5 shrink-0 drop-shadow-[0_0_6px_rgba(167,139,250,0.85)]" />
              {activeTab === 'ai_agent' && <span className="relative text-xs font-medium">AI</span>}
            </button>

            <NotificationBell
              role={effectiveRole}
              authKey={authKey}
              refreshTrigger={alertsVersion}
              onOpenHost={(hid) => setBellHostId(hid)}
              onOpenAiAgent={() => setActiveTab('ai_agent')}
              onAlertsChanged={bumpAlertsVersion}
            />

            <Button
              variant="outline"
              size="icon"
              onClick={() => setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))}
              title={theme === 'dark' ? 'Tryb jasny' : 'Tryb ciemny'}
              aria-label="Przełącz motyw"
            >
              {theme === 'dark' ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
            </Button>

            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                refreshCoreData();
                bumpAlertsVersion();
              }}
              title="Odśwież"
              aria-label="Odśwież"
            >
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

        <div key={authKey}>
          <TabsContent value="dashboard" className="mt-0">
            <DashboardTab
              role={effectiveRole}
              hosts={hosts}
              changes={changes}
              summary={summary}
              onRefresh={refreshCoreData}
              onOpenGroupSearch={handleOpenGroupSearch}
              onCreateSignature={handleCreateSignatureFromHost}
            />
          </TabsContent>
          <TabsContent value="hosts" className="mt-0">
            <HostsTab
              role={effectiveRole}
              hosts={hosts}
              onRefresh={refreshCoreData}
              onCreateSignature={handleCreateSignatureFromHost}
            />
          </TabsContent>
          <TabsContent value="groups" className="mt-0">
            <GroupsTab
              role={effectiveRole}
              initialSearch={groupSearchQuery}
              onInitialSearchConsumed={handleGroupSearchConsumed}
              onRefreshAll={refreshCoreData}
              onExportGroupToDefectDojo={handleExportGroupToDefectDojo}
            />
          </TabsContent>
          <TabsContent value="changes" className="mt-0">
            <ChangesTab role={effectiveRole} changes={changes} onRefresh={refreshCoreData} />
          </TabsContent>
          <TabsContent value="targets" className="mt-0">
            <TargetsScansTab role={effectiveRole} onRefreshAll={refreshCoreData} />
          </TabsContent>
          <TabsContent value="signatures" className="mt-0">
            <SignaturesTab
              role={effectiveRole}
              initialDraft={signatureDraft}
              onDraftConsumed={handleSignatureDraftConsumed}
            />
          </TabsContent>
          <TabsContent value="ai_agent" className="mt-0">
            <AiAgentTab
              role={effectiveRole}
              isCurrentUserScoped={Boolean(session?.scope_restricted)}
              alertsVersion={alertsVersion}
              onRefreshAll={refreshCoreData}
              onAlertsChanged={bumpAlertsVersion}
              onCreateSignature={handleCreateSignatureFromHost}
            />
          </TabsContent>
          <TabsContent value="defectdojo" className="mt-0">
            <DefectDojoTab
              role={effectiveRole}
              hosts={hosts}
              preselectedHostIds={ddPreselect?.hostIds ?? null}
              preselectedGroupLabel={ddPreselect?.label ?? null}
              onPreselectionConsumed={handleDdPreselectConsumed}
            />
          </TabsContent>
          <TabsContent value="rbac" className="mt-0">
            <RbacAuditTab
              role={effectiveRole}
              currentUsername={session?.username ?? null}
              isCurrentUserScoped={Boolean(session?.scope_restricted)}
              onRolesChanged={refreshRoles}
            />
          </TabsContent>
        </div>

        <HostDetailSheet
          hostId={bellHostId}
          onClose={handleCloseBellHost}
          role={effectiveRole}
          onRefresh={refreshCoreData}
          onAlertsChanged={bumpAlertsVersion}
          onCreateSignature={handleCreateSignatureFromHost}
        />
      </main>
    </Tabs>
  );
}
