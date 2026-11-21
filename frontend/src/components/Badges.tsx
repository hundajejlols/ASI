import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Info,
  Minus,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import type { Severity } from '../types';
import { Badge, type BadgeVariant } from './ui/badge';

export function HostStatusBadge({ status, missedScans }: { status: string; missedScans?: number }) {
  let variant: BadgeVariant = 'outline';
  let Icon = Archive;

  if (status === 'online') {
    variant = 'default';
    Icon = CheckCircle2;
  } else if (status === 'unstable') {
    variant = 'secondary';
    Icon = AlertTriangle;
  } else if (status === 'offline') {
    variant = 'outline';
    Icon = XCircle;
  }

  return (
    <Badge variant={variant} className="font-mono">
      <Icon className="h-3 w-3 shrink-0" />
      <span>
        {status}
        {typeof missedScans === 'number' && missedScans > 0 ? ` (${missedScans})` : ''}
      </span>
    </Badge>
  );
}

export function ChangeTypeBadge({ type }: { type: string }) {
  let variant: BadgeVariant = 'outline';
  let Icon = RefreshCw;

  if (type === 'host_new' || type === 'service_new') {
    variant = 'default';
    Icon = Plus;
  } else if (type === 'host_offline' || type === 'service_closed') {
    variant = 'outline';
    Icon = Minus;
  } else if (type === 'host_recovered') {
    variant = 'secondary';
    Icon = RotateCcw;
  } else if (type === 'signature_matched') {
    variant = 'default';
    Icon = ShieldAlert;
  } else {
    variant = 'secondary';
    Icon = RefreshCw;
  }

  return (
    <Badge variant={variant} className="font-mono">
      <Icon className="h-3 w-3 shrink-0" />
      <span>{type}</span>
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  let variant: BadgeVariant = 'outline';
  let Icon = Info;

  if (severity === 'critical' || severity === 'high') {
    variant = 'default';
    Icon = ShieldAlert;
  } else if (severity === 'medium') {
    variant = 'secondary';
    Icon = AlertTriangle;
  } else {
    variant = 'outline';
    Icon = Info;
  }

  return (
    <Badge variant={variant} className="uppercase tracking-wider font-mono text-[10px]">
      <Icon className="h-2.5 w-2.5 shrink-0" />
      <span>{severity}</span>
    </Badge>
  );
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('pl-PL', {
      dateStyle: 'short',
      timeStyle: 'medium',
    });
  } catch {
    return iso;
  }
}
