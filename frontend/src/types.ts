export type BuiltinUserRole = 'admin' | 'add_delete_modify' | 'modify_read' | 'read_only';
export type UserRole = string;

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SignatureMatchType =
  | 'header'
  | 'cookie'
  | 'favicon_hash'
  | 'html_fragment'
  | 'path_probe'
  | 'footer_version';

export interface HealthResponse {
  status: string;
  services: {
    postgres: string;
    redis: string;
  };
}

export interface RoleItem {
  name: string;
  description: string | null;
  permissions: string[];
  is_system: boolean;
  created_at?: string | null;
}

export interface UserScopeConfig {
  ips: string[];
  cidrs: string[];
  ip_ranges: string[];
  group_ids: string[];
  host_ids: string[];
}

export interface UserScopeSummary {
  restricted: boolean;
  matched_hosts_count: number;
  sample_ips: string[];
  ips_count: number;
  cidrs_count: number;
  ip_ranges_count: number;
  group_ids_count: number;
  host_ids_count: number;
  group_names: string[];
}

export interface UserItem {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  scope_restricted: boolean;
  allowed_scope: UserScopeConfig;
  scope_summary?: UserScopeSummary;
  created_at: string;
}

export interface AuditLogItem {
  id: number;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface AuthSession {
  token: string;
  username: string;
  role: string;
  permissions: string[];
  scope_restricted?: boolean;
  scope_summary?: UserScopeSummary | null;
}

export interface OverrideOut {
  id: string;
  entity_type: 'host' | 'service';
  entity_id: string;
  custom_label: string | null;
  owner_unit: string | null;
  criticality: Severity | null;
  tags: string[];
  is_false_positive: boolean;
  is_ignored: boolean;
  notes: string | null;
  updated_at: string;
}

export interface HTTPFingerprintOut {
  id: string;
  url: string;
  scheme: string;
  status_code: number | null;
  response_time_ms?: number | null;
  probe_error?: string | null;
  title: string | null;
  redirect_chain: string[];
  headers: Record<string, string>;
  cookies: string[];
  favicon_mmh3_hash: string | null;
  tls_subject: string | null;
  tls_issuer: string | null;
  tls_not_after: string | null;
  tls_san: string[];
  tls_is_self_signed?: boolean;
  technologies: string[];
  tech_confidence?: Record<string, string>;
  is_admin_panel: boolean;
  is_staging_env: boolean;
  captured_at: string;
}

export interface SignatureMatchOut {
  id: string;
  signature_id: string;
  signature_name: string;
  severity: Severity;
  matched_evidence: string | null;
  matched_at: string;
}

export interface ServiceOut {
  id: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
  missed_scans: number;
  first_seen_at: string;
  last_seen_at: string;
  latest_http_fingerprint: HTTPFingerprintOut | null;
  signature_matches: SignatureMatchOut[];
  override: OverrideOut | null;
}

export interface HostSummary {
  id: string;
  ip_address: string;
  hostname: string | null;
  status: 'online' | 'unstable' | 'offline' | 'archived';
  missed_scans: number;
  open_services_count: number;
  is_admin_panel?: boolean;
  is_staging_env?: boolean;
  technologies?: string[];
  signature_matches_count?: number;
  highest_severity?: Severity;
  priority_score?: number;
  first_seen_at: string;
  last_seen_at: string;
  override: OverrideOut | null;
}

export interface ScanRunInfo {
  id: string;
  status: 'queued' | 'running' | 'paused_window' | 'completed' | 'failed' | 'cancelled';
  total_chunks: number;
  completed_chunks: number;
  duration_seconds: number | null;
  window_deadline_at: string | null;
  started_at: string | null;
  paused_at: string | null;
  finished_at: string | null;
  created_at: string | null;
}

export interface DashboardSummary {
  kpi: {
    total_hosts: number;
    online_hosts: number;
    unstable_hosts: number;
    offline_hosts: number;
    archived_hosts: number;
    total_open_services: number;
    total_changes: number;
    active_signature_matches: number;
  };
  changes_timeline: {
    date: string;
    total: number;
    high_or_med: number;
    new: number;
    offline: number;
    tls_changed?: number;
    tech_changed?: number;
  }[];
  changes_by_type: Record<string, number>;
  time_of_day_analysis: {
    day_06_22: { total: number; host_offline: number; host_recovered: number; service_changes: number };
    night_22_06: { total: number; host_offline: number; host_recovered: number; service_changes: number };
  };
  service_groups: {
    by_technology: { key: string; count: number; sample_endpoints: string[] }[];
    by_product: { key: string; count: number; sample_endpoints: string[] }[];
    by_favicon_mmh3: { key: string; count: number; sample_endpoints: string[] }[];
  };
}

export interface ScanCompareResult {
  run_a: ScanRunInfo;
  run_b: ScanRunInfo;
  summary: {
    run_a_endpoints: number;
    run_b_endpoints: number;
    added: number;
    removed: number;
    changed: number;
    unchanged: number;
    change_events_between: number;
  };
  added_endpoints: Array<{ host_ip: string; port: number; protocol: string; url: string; title: string | null; technologies: string[] }>;
  removed_endpoints: Array<{ host_ip: string; port: number; protocol: string; url: string; title: string | null; technologies: string[] }>;
  changed_endpoints: Array<{ endpoint: string; diffs: Record<string, { run_a: unknown; run_b: unknown }> }>;
  events_between: Array<{
    id: string;
    change_type: string;
    severity: Severity;
    host_ip: string | null;
    service_port: number | null;
    previous_value: Record<string, unknown> | null;
    current_value: Record<string, unknown> | null;
    detected_at: string;
  }>;
}

export interface HostDetail {
  id: string;
  ip_address: string;
  hostname: string | null;
  status: 'online' | 'unstable' | 'offline' | 'archived';
  missed_scans: number;
  first_seen_at: string;
  last_seen_at: string;
  last_scan_run_id: string | null;
  override: OverrideOut | null;
  services: ServiceOut[];
}

export interface TimelineDayDetails {
  date: string;
  total: number;
  hourly: Array<{
    hour: number;
    total: number;
    high_or_med: number;
    new: number;
    offline: number;
  }>;
  by_type: Array<{ change_type: string; count: number }>;
  by_severity: Record<string, number>;
  sample_events: Array<{
    id: string;
    host_ip: string | null;
    service_port: number | null;
    service_protocol: string | null;
    change_type: string;
    severity: Severity;
    detected_at: string;
  }>;
}

export interface ChangeEvent {
  id: string;
  scan_run_id: string;
  host_id: string;
  host_ip: string | null;
  service_id: string | null;
  service_port: number | null;
  service_protocol: string | null;
  change_type: string;
  severity: Severity;
  previous_value: Record<string, unknown> | null;
  current_value: Record<string, unknown> | null;
  acknowledged: boolean;
  detected_at: string;
}

export interface TargetItem {
  id: string;
  group_id: string;
  raw_value: string;
  type: 'ip' | 'cidr' | 'domain';
  is_active: boolean;
  created_at: string;
}

export interface ScheduleItem {
  id: string;
  name: string;
  target_group_id: string;
  target_group_name?: string | null;
  target_group_type?: string | null;
  profile_id: string;
  cron_expression: string;
  window_start: string;
  window_end: string;
  timezone: string;
  missed_scans_threshold: number;
  is_enabled: boolean;
  in_window_now: boolean;
  remaining_window_minutes: number | null;
  created_at: string;
}

export type HostStatusValue = 'online' | 'unstable' | 'offline' | 'archived';
export type AutoGroupCategory = 'technology' | 'port' | 'classification' | 'signature' | 'override';

export interface GroupFilterRules {
  match_mode: 'all' | 'any';
  technologies: string[];
  ports: number[];
  service_names: string[];
  products: string[];
  signature_ids: string[];
  favicon_hashes: string[];
  is_admin_panel: boolean | null;
  is_staging_env: boolean | null;
  statuses: HostStatusValue[];
  owner_units: string[];
  tags: string[];
  cidr_scope: string | null;
  exclude_ignored: boolean;
}

export interface AutoGroupItem {
  key: string;
  category: AutoGroupCategory;
  label: string;
  description: string;
  host_count: number;
  host_ids: string[];
  sample_ips: string[];
  matched_ports: number[];
  suggested_ports_spec: string | null;
  filter_rules: GroupFilterRules;
}

export interface GroupFacets {
  technologies: string[];
  ports: number[];
  service_names: string[];
  products: string[];
  owner_units: string[];
  tags: string[];
  favicons: string[];
  signatures: Array<{ id: string; name: string; severity: Severity }>;
}

export interface AutoGroupsResponse {
  generated_at: string;
  total_auto_groups: number;
  facets: GroupFacets;
  groups: AutoGroupItem[];
}

export interface GroupMemberHost {
  id: string;
  ip_address: string;
  hostname: string | null;
  status: HostStatusValue;
  missed_scans: number;
  open_ports: number[];
  matched_ports: number[];
  technologies: string[];
  is_admin_panel: boolean;
  is_staging_env: boolean;
  custom_label: string | null;
  owner_unit: string | null;
  tags: string[];
}

export interface GroupPreviewResponse {
  total_hosts: number;
  host_ids: string[];
  ips: string[];
  matched_ports: number[];
  suggested_ports_spec: string | null;
  hosts: GroupMemberHost[];
  truncated: boolean;
}

export interface SavedGroupItem {
  id: string;
  name: string;
  description: string | null;
  environment: string;
  group_type: 'static' | 'dynamic' | string;
  filter_rules: Partial<GroupFilterRules>;
  member_count: number;
  host_ids: string[];
  sample_ips: string[];
  matched_ports: number[];
  suggested_ports_spec: string | null;
  created_at: string;
}

export interface GroupScanResponse {
  dry_run: boolean;
  queued?: boolean;
  scan_run_id?: string;
  status?: string;
  group_label: string;
  ports_mode: 'profile' | 'matched_ports' | 'custom';
  ports?: string;
  matched_hosts_count: number;
  matched_ips: string[];
  total_chunks: number;
  chunks: string[];
  estimated_duration_seconds?: number;
  window_deadline_utc?: string;
}

export interface SignatureItem {
  id: string;
  name: string;
  description: string | null;
  severity: Severity;
  match_type: SignatureMatchType;
  pattern: string;
  probe_path: string | null;
  expected_status: number | null;
  is_enabled: boolean;
}

export interface SignaturePortable {
  name: string;
  description: string | null;
  severity: Severity;
  match_type: SignatureMatchType;
  pattern: string;
  probe_path: string | null;
  expected_status: number | null;
  is_enabled: boolean;
}

export interface SignatureExportBundle {
  schema_version: string;
  exported_at: string;
  count: number;
  signatures: SignaturePortable[];
}

export type SignatureImportItemStatus =
  | 'created'
  | 'updated'
  | 'skipped'
  | 'error'
  | 'would_create'
  | 'would_update'
  | 'would_skip';

export interface SignatureImportItemResult {
  index: number;
  name: string;
  match_type: string | null;
  severity: string | null;
  pattern: string | null;
  status: SignatureImportItemStatus;
  message: string;
}

export interface SignatureImportResponse {
  dry_run: boolean;
  on_conflict: 'skip' | 'overwrite' | 'error';
  summary: {
    total: number;
    created: number;
    updated: number;
    skipped: number;
    errors: number;
  };
  items: SignatureImportItemResult[];
}

export interface SignatureTestDbMatch {
  host_id: string;
  ip_address: string;
  hostname: string | null;
  port: number;
  protocol: string;
  url: string;
  evidence: string;
}

export interface SignatureTestResponse {
  valid: boolean;
  match_type: SignatureMatchType;
  pattern: string;
  probe_path: string | null;
  expected_status: number | null;
  sample_match: boolean;
  sample_evidence: string | null;
  sample_note: string | null;
  db_test: {
    supported: boolean;
    note: string | null;
    services_checked: number;
    matches_count: number;
    matches: SignatureTestDbMatch[];
  } | null;
}

export interface ObservedArtifactsResponse {
  header_names: string[];
  cookies: string[];
  favicons: Array<{
    hash: string;
    count: number;
    sample_endpoints: string[];
  }>;
}

export interface SignatureDraft {
  name?: string;
  description?: string;
  severity?: Severity;
  match_type: SignatureMatchType;
  header_name?: string;
  header_value?: string;
  header_op?: 'exists' | 'contains' | 'equals' | 'starts_with' | 'version';
  cookie_name?: string;
  favicon_hash?: string;
  pattern?: string;
  probe_path?: string;
  expected_status?: number | null;
  sample_hint?: string;
}

export interface DefectDojoConfig {
  configured: boolean;
  base_url: string | null;
  product_type_name: string;
  engagement_name: string;
  verify_tls: boolean;
  is_active: boolean;
  has_api_token: boolean;
  updated_at: string | null;
}

export interface DefectDojoDryRunAsset {
  host_id: string;
  ip_address: string;
  hostname: string | null;
  product_name: string;
  product_type_name: string;
  product_type_source: 'owner_unit' | 'default';
  engagement_name: string;
  test_title: string;
  findings_count: number;
  form_fields: Record<string, string>;
  payload: { findings: Array<Record<string, unknown>> };
}

export interface DefectDojoExportHostResult {
  host_id: string;
  ip_address: string;
  hostname?: string | null;
  product_name: string;
  product_type_name: string | null;
  product_type_source: 'owner_unit' | 'default' | 'existing_in_defectdojo';
  engagement_name?: string;
  action?: 'created' | 'updated';
  status: 'exported' | 'failed';
  status_code?: number;
  product_id?: number | null;
  product_type_id?: number | null;
  engagement_id?: number | null;
  test_id?: number | null;
  findings_count: number;
  error?: string;
}

export interface DefectDojoExportResponse {
  dry_run: boolean;
  configured?: boolean;
  exported?: boolean;
  partial_failure?: boolean;
  mode: string;
  strategy?: string;
  target_reimport_url?: string;
  default_product_type_name: string;
  engagement_name: string;
  test_title: string;
  close_old_findings: boolean;
  stats: {
    hosts_evaluated: number;
    assets_to_export: number;
    hosts_exported: number;
    skipped_ignored_or_fp: number;
    skipped_offline: number;
    skipped_no_findings: number;
    total_findings: number;
    only_interesting: boolean;
    assets_exported?: number;
    assets_created?: number;
    assets_updated?: number;
    assets_failed?: number;
  };
  assets_preview_truncated?: boolean;
  assets_preview_limit?: number;
  assets?: DefectDojoDryRunAsset[];
  results?: DefectDojoExportHostResult[];
}
