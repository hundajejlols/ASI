import {
  ArrowUpRight,
  Bell,
  BellRing,
  Check,
  CheckCheck,
  CheckCircle2,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { apiFetch, hasPermission } from '../api';
import type { AiAlertItem, AiAlertsResponse, UserRole } from '../types';
import { formatTime } from './Badges';
import { Badge } from './ui/badge';
import { Button } from './ui/button';

interface Props {
  role: UserRole;
  authKey: string;
  refreshTrigger: number;
  onOpenHost: (hostId: string) => void;
  onOpenAiAgent: () => void;
  onAlertsChanged?: () => void;
}

export function NotificationBell({
  role,
  authKey,
  refreshTrigger,
  onOpenHost,
  onOpenAiAgent,
  onAlertsChanged,
}: Props) {
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<AiAlertItem[]>([]);
  const [urgentUnack, setUrgentUnack] = useState(0);
  const [ackingId, setAckingId] = useState<string | null>(null);
  const [ackingAll, setAckingAll] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const canModify = hasPermission(role, 'modify');

  const loadUrgentAlerts = useCallback(async () => {
    try {
      const res = await apiFetch<AiAlertsResponse>('/ai-agent/alerts?only_urgent=true&limit=50', role);
      setAlerts(res.alerts || []);
      setUrgentUnack(res.summary?.urgent_unacknowledged ?? 0);
    } catch {
      setAlerts([]);
      setUrgentUnack(0);
    }
  }, [role, authKey]);

  useEffect(() => {
    loadUrgentAlerts();
  }, [loadUrgentAlerts, refreshTrigger]);

  // Lekki polling co 20s (łapie też automatyczną analizę AI po skanie w tle)
  useEffect(() => {
    const timer = setInterval(() => {
      loadUrgentAlerts();
    }, 20000);
    return () => clearInterval(timer);
  }, [loadUrgentAlerts]);

  // Zamykanie kliknięciem poza panelem lub Escape
  useEffect(() => {
    if (!open) return;
    function handleOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', handleOutside);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleOutside);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  async function handleAcknowledge(alertId: string) {
    if (!canModify) return;
    setAckingId(alertId);
    try {
      await apiFetch(`/ai-agent/alerts/${alertId}/acknowledge`, role, {
        method: 'PATCH',
        body: JSON.stringify({ acknowledged: true }),
      });
      await loadUrgentAlerts();
      onAlertsChanged?.();
    } catch {
      // ignore
    } finally {
      setAckingId(null);
    }
  }

  async function handleAcknowledgeAll() {
    if (!canModify) return;
    const unack = alerts.filter((a) => !a.acknowledged);
    if (unack.length === 0) return;
    setAckingAll(true);
    try {
      await Promise.all(
        unack.map((a) =>
          apiFetch(`/ai-agent/alerts/${a.id}/acknowledge`, role, {
            method: 'PATCH',
            body: JSON.stringify({ acknowledged: true }),
          })
        )
      );
      await loadUrgentAlerts();
      onAlertsChanged?.();
    } catch {
      // ignore
    } finally {
      setAckingAll(false);
    }
  }

  return (
    <div ref={containerRef} className="relative">
      <Button
        type="button"
        variant={urgentUnack > 0 ? 'default' : 'outline'}
        size="icon"
        onClick={() => {
          setOpen((v) => {
            const next = !v;
            if (next) loadUrgentAlerts();
            return next;
          });
        }}
        className="relative"
        title={
          urgentUnack > 0
            ? `Pilne alarmy administratora: ${urgentUnack}`
            : 'Alarmy administratora (brak nowych)'
        }
        aria-label="Alarmy administratora"
      >
        {urgentUnack > 0 ? <BellRing className="h-3.5 w-3.5" /> : <Bell className="h-3.5 w-3.5" />}
        {urgentUnack > 0 && (
          <span className="absolute -right-1.5 -top-1.5 min-w-[16px] h-4 px-1 rounded-full bg-background text-foreground border border-foreground text-[9px] font-mono font-bold flex items-center justify-center leading-none">
            {urgentUnack > 9 ? '9+' : urgentUnack}
          </span>
        )}
      </Button>

      {open && (
        <div className="absolute right-0 mt-2 w-[360px] sm:w-[420px] rounded-lg border border-border bg-background text-foreground shadow-xl z-50 overflow-hidden">
          {/* Nagłówek powiadomień */}
          <div className="px-3.5 py-2.5 border-b border-border flex items-center justify-between gap-2 bg-muted/30">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-foreground">Alarmy administratora</span>
              <Badge variant={urgentUnack > 0 ? 'default' : 'secondary'} className="font-mono text-[10px]">
                {urgentUnack} nowe
              </Badge>
            </div>
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                onOpenAiAgent();
              }}
              className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
            >
              <span>AI Agent</span>
              <ArrowUpRight className="h-3 w-3" />
            </button>
          </div>

          {/* Lista pilnych alertów */}
          <div className="max-h-[420px] overflow-y-auto divide-y divide-border/70">
            {alerts.length === 0 ? (
              <div className="py-10 px-4 text-center space-y-2">
                <ShieldCheck className="h-6 w-6 mx-auto text-muted-foreground" />
                <p className="text-xs font-medium text-foreground">Brak pilnych alarmów</p>
                <p className="text-[11px] text-muted-foreground">
                  Żaden sprawdzony host w Twoim zakresie nie wymaga obecnie pilnej reakcji administratora.
                </p>
              </div>
            ) : (
              alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-3 space-y-2 text-xs transition-colors hover:bg-muted/25 ${
                    alert.acknowledged ? 'opacity-65' : ''
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                      <Badge
                        variant={alert.acknowledged ? 'outline' : 'default'}
                        className="font-mono uppercase text-[9px] px-1.5 py-0"
                      >
                        {alert.urgency}
                      </Badge>
                      <button
                        type="button"
                        onClick={() => {
                          setOpen(false);
                          onOpenHost(alert.host_id);
                        }}
                        className="font-mono font-semibold text-foreground underline underline-offset-2 hover:opacity-80"
                      >
                        {alert.ip_address || alert.host_id.slice(0, 8)}
                      </button>
                      {alert.owner_unit && (
                        <Badge variant="secondary" className="font-mono text-[9px] px-1.5 py-0">
                          {alert.owner_unit}
                        </Badge>
                      )}
                    </div>
                    <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                      {formatTime(alert.created_at)}
                    </span>
                  </div>

                  <div className="font-medium text-foreground leading-snug">{alert.title}</div>

                  {alert.cves.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {alert.cves.slice(0, 4).map((cve) => (
                        <Badge key={cve} variant="secondary" className="font-mono text-[9px] px-1.5 py-0">
                          {cve}
                        </Badge>
                      ))}
                    </div>
                  )}

                  <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-3">
                    {alert.admin_alert_message || alert.summary}
                  </p>

                  <div className="flex items-center justify-between gap-2 pt-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-6 px-2 text-[10px]"
                      onClick={() => {
                        setOpen(false);
                        onOpenHost(alert.host_id);
                      }}
                    >
                      <Server className="h-3 w-3" />
                      Szczegóły hosta
                    </Button>

                    {alert.acknowledged ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono text-muted-foreground">
                        <CheckCircle2 className="h-3 w-3" />
                        Potwierdzono
                      </span>
                    ) : canModify ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-[10px]"
                        disabled={ackingId === alert.id}
                        onClick={() => handleAcknowledge(alert.id)}
                      >
                        <Check className="h-3 w-3" />
                        {ackingId === alert.id ? '...' : 'Potwierdź odbiór'}
                      </Button>
                    ) : null}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Stopka */}
          {alerts.length > 0 && (
            <div className="px-3.5 py-2 border-t border-border bg-muted/20 flex items-center justify-between gap-2 text-[11px]">
              {canModify && urgentUnack > 0 ? (
                <button
                  type="button"
                  disabled={ackingAll}
                  onClick={handleAcknowledgeAll}
                  className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
                >
                  <CheckCheck className="h-3.5 w-3.5" />
                  <span>{ackingAll ? 'Potwierdzanie...' : 'Potwierdź wszystkie'}</span>
                </button>
              ) : (
                <span className="text-muted-foreground">Wszystkie potwierdzone</span>
              )}
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onOpenAiAgent();
                }}
                className="font-medium text-foreground underline underline-offset-2"
              >
                Zobacz wszystkie oceny
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
