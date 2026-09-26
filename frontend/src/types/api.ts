// Mirrors the backend response schemas (backend/app/schemas/*). Keep in sync with
// docs/openapi.json.

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string | null;
    details?: { loc: (string | number)[]; msg: string; type: string }[];
  };
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface HealthResponse {
  status: "ok";
  version: string;
}

export interface ReadinessResponse {
  status: "ok" | "unavailable";
  checks: {
    database: "up" | "down";
    migrations: "current" | "pending" | "unknown";
  };
}

export type Role = "ADMIN" | "ANALYST" | "VIEWER";

export interface User {
  id: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface TokenResponse {
  access_token: string;
  expires_in: number;
  user: User;
}

export type AuditResult = "SUCCESS" | "FAILURE" | "DENIED";

export interface AuditEntry {
  id: string;
  occurred_at: string;
  action: string;
  result: AuditResult;
  actor_id: string | null;
  actor_label: string | null;
  entity_type: string | null;
  entity_id: string | null;
  client_ip: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
}

// ---------- alerts (mirror backend/app/schemas/alert.py) ----------

export type AlertStatus = "NEW" | "TRIAGED" | "IN_PROGRESS" | "RESOLVED" | "FALSE_POSITIVE";
export type Disposition = "confirmed_malicious" | "benign_expected";
export type Level = "low" | "medium" | "high" | "critical";

export interface AlertSummary {
  id: string;
  rule_id: string;
  title: string;
  severity: Level;
  confidence: "low" | "medium" | "high";
  status: AlertStatus;
  disposition: Disposition | null;
  priority_score: number;
  priority_band: Level;
  host: string | null;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  event_count: number;
  evidence_truncated: boolean;
  detection_count: number;
  first_event_at: string;
  last_event_at: string;
  created_at: string;
  updated_at: string;
  simulated: boolean;
}

export interface PriorityFactor {
  factor: string;
  value: string;
  points: number;
}

export interface AlertTechnique {
  technique: string;
  name: string;
  tactics: string[];
  reason: string;
  attack_version: string;
  url: string;
}

export interface AlertActivity {
  at: string;
  actor: string | null;
  from_status: string;
  to_status: string;
  disposition: string | null;
  reason: string | null;
}

export interface RelatedAlert {
  id: string;
  rule_id: string;
  title: string;
  status: AlertStatus;
  priority_score: number;
  priority_band: Level;
  last_event_at: string;
  shared: string[];
}

export interface AlertHistoryEntry {
  run_id: string;
  at: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  new_evidence: number;
  explanation: string;
}

export interface AlertDetail extends AlertSummary {
  rule_version: number;
  indicator: string | null;
  kind: string;
  category: string;
  description: string;
  target_username: string | null;
  asset_id: string | null;
  asset_hostname: string | null;
  identity_id: string | null;
  identity_username: string | null;
  priority_breakdown: PriorityFactor[];
  risk_model_version: string;
  group_values: Record<string, string>;
  explanation: string;
  facts: Record<string, unknown>;
  entities: Record<string, string[]>;
  investigation: string[];
  response: string[];
  mitre: AlertTechnique[];
  history: AlertHistoryEntry[];
  peak_count: number;
  previous_alert_id: string | null;
  triaged_at: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  status_changed_at: string | null;
  status_changed_by: string | null;
  status_note: string | null;
  allowed_transitions: AlertStatus[];
  activity: AlertActivity[];
  related: RelatedAlert[];
  incident_id: string | null;
}

export interface EvidenceEvent {
  id: string;
  timestamp: string;
  source_type: string;
  event_category: string;
  event_action: string;
  event_outcome: string;
  host: string | null;
  username: string | null;
  target_username: string | null;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  process_name: string | null;
  command_line: string | null;
  message: string | null;
  simulated: boolean;
  raw_text: string;
  raw_truncated: boolean;
}

export interface TransitionRequest {
  status: AlertStatus;
  disposition?: Disposition;
  reason?: string;
}
