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
  incident_number: number | null;
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

// ---------- incidents (mirror backend/app/schemas/incident.py) ----------

export type IncidentStatus =
  | "OPEN"
  | "TRIAGED"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED"
  | "CLOSED";
export type IncidentDisposition = "confirmed_malicious" | "benign_expected" | "false_positive";
export type EvidenceTag = "initial_access" | "privilege" | "persistence" | "benign" | "needs_review";

export interface UserRef {
  id: string;
  email: string;
}

export interface IncidentSummary {
  id: string;
  number: number;
  title: string;
  status: IncidentStatus;
  severity: Level;
  risk_score: number;
  risk_band: Level;
  alert_count: number;
  hosts: string[];
  usernames: string[];
  source_ips: string[];
  tactics: string[];
  first_activity_at: string;
  last_activity_at: string;
  created_at: string;
  updated_at: string;
  simulated: boolean;
  assigned_to: UserRef | null;
}

export interface LinkedAlert {
  alert: AlertSummary;
  link_strength: "STRONG" | "MEDIUM" | "WEAK" | "MANUAL" | "ORIGIN";
  shared_entities: string[];
  reason: string;
  link_source: "engine" | "analyst";
  linked_at: string;
}

export interface NotePublic {
  id: string;
  author: string | null;
  body: string;
  created_at: string;
}

export interface PinPublic {
  id: string;
  event_id: string | null;
  alert_id: string | null;
  label: string;
  tag: EvidenceTag;
  comment: string | null;
  pinned_by: string | null;
  pinned_at: string;
}

export interface IncidentActivityEntry {
  at: string;
  actor: string | null;
  kind: string;
  details: Record<string, unknown>;
}

export interface IncidentTechnique {
  technique: string;
  name: string;
  tactics: string[];
  attack_version: string;
  url: string;
  rules: string[];
  reasons: string[];
}

export interface IncidentDetail extends IncidentSummary {
  summary: string;
  created_reason: string;
  risk_breakdown: PriorityFactor[];
  risk_model_version: string;
  techniques: string[];
  disposition: IncidentDisposition | null;
  resolution: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  closed_at: string | null;
  title_edited: boolean;
  related_incident: { id: string; number: number; title: string; status: IncidentStatus } | null;
  alerts: LinkedAlert[];
  notes: NotePublic[];
  evidence: PinPublic[];
  activity: IncidentActivityEntry[];
  mitre: IncidentTechnique[];
  response: { rule_id: string; title: string; steps: string[] }[];
  allowed_transitions: IncidentStatus[];
}

export interface TimelineEvent {
  category: string;
  action: string;
  outcome: string;
  host: string | null;
  username: string | null;
  target_username: string | null;
  source_ip: string | null;
  process_name: string | null;
  command_line: string | null;
  raw_text: string;
  rules: string[];
  simulated: boolean;
}

export interface TimelineEntry {
  at: string;
  kind: "event" | "alert" | "activity";
  id: string;
  event: TimelineEvent | null;
  alert: { rule_id: string; title: string; severity: Level; priority_score: number; status: AlertStatus } | null;
  activity: { kind: string; actor: string | null; details: Record<string, unknown> } | null;
}

export interface TimelinePage {
  items: TimelineEntry[];
  next_cursor: string | null;
  limit: number;
}

export interface CorrelationSettings {
  correlation_window_minutes: number;
  sequence_window_minutes: number;
}
