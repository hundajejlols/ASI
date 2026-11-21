import type { RoleItem, UserRole } from './types';

export const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export type Permission = 'read' | 'modify' | 'add' | 'delete' | 'manage_users' | 'manage_integrations';

const DEFAULT_ROLE_PERMS: Record<string, Set<Permission>> = {
  admin: new Set(['read', 'modify', 'add', 'delete', 'manage_users', 'manage_integrations']),
  add_delete_modify: new Set(['read', 'modify', 'add', 'delete']),
  modify_read: new Set(['read', 'modify']),
  read_only: new Set(['read']),
};

let dynamicRolePerms: Record<string, Set<Permission>> = { ...DEFAULT_ROLE_PERMS };
let activeJwtToken: string | null = null;

export function setAuthToken(token: string | null): void {
  activeJwtToken = token;
}

export function getAuthToken(): string | null {
  return activeJwtToken;
}

export function syncDynamicRoles(roles: RoleItem[]): void {
  const next: Record<string, Set<Permission>> = { ...DEFAULT_ROLE_PERMS };
  for (const r of roles) {
    next[r.name] = new Set((r.permissions || []) as Permission[]);
  }
  dynamicRolePerms = next;
}

export function hasPermission(role: UserRole, perm: Permission): boolean {
  return dynamicRolePerms[role]?.has(perm) ?? DEFAULT_ROLE_PERMS[role]?.has(perm) ?? false;
}

function buildAuthHeaders(role: UserRole, baseHeaders?: HeadersInit): Headers {
  const headers = new Headers(baseHeaders || {});
  if (activeJwtToken) {
    headers.set('Authorization', `Bearer ${activeJwtToken}`);
  } else {
    headers.set('X-Dev-Role', role);
  }
  return headers;
}

export async function apiFetch<T>(
  path: string,
  role: UserRole,
  options: RequestInit = {}
): Promise<T> {
  const headers = buildAuthHeaders(role, options.headers);
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const errData = await res.json();
      if (errData?.detail) {
        detail = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
      }
    } catch {
      // ignore non-json error body
    }
    throw new Error(detail);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

export async function apiFetchPaginated<T>(
  path: string,
  role: UserRole
): Promise<{ data: T; totalCount: number }> {
  const headers = buildAuthHeaders(role);
  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const errData = await res.json();
      if (errData?.detail) {
        detail = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(detail);
  }
  const data = (await res.json()) as T;
  const totalHeader = res.headers.get('X-Total-Count');
  const totalCount = totalHeader ? Number(totalHeader) : Array.isArray(data) ? data.length : 0;
  return { data, totalCount };
}

export async function downloadExport(format: 'json' | 'csv', role: UserRole): Promise<void> {
  const headers = buildAuthHeaders(role);
  const res = await fetch(`${API_BASE}/scans/export?format=${format}`, { headers });
  if (!res.ok) {
    throw new Error(`Eksport nie powiódł się (HTTP ${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `asi_export.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
