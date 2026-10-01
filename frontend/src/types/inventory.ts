// Events, inventory, detection rules and the dashboard (mirror backend/app/schemas: ingestion,
// context, detection, dashboard).
import type { AlertSummary, IncidentSummary, Level } from "./api";

export interface EventRecord {
  id: string;
  raw_event_id: string;
  source_id: string;
  source_type: string;
  timestamp: string;
  ingested_at: string;
  host: string | null;
  host_ip: string | null;
  event_category: string;
  event_action: string;
  event_outcome: string;
  username: string | null;
  user_domain: string | null;
  target_username: string | null;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
  service: string | null;
  process_name: string | null;
  parent_process_name: string | null;
  command_line: string | null;
  session_id: string | null;
  message: string | null;
  attributes: Record<string, unknown>;
  source_ip_scope: string | null;
  asset_id: string | null;
  asset_criticality: string | null;
  identity_id: string | null;
  identity_privileged: boolean | null;
  simulated: boolean;
}

export interface EventPage {
  items: EventRecord[];
  next_cursor: string | null;
  limit: number;
}

export interface EventDetail extends EventRecord {
  raw: {
    id: string;
    batch_id: string;
    received_at: string;
    parse_status: string;
    parse_detail: string | null;
    size_bytes: number;
    text: string | null; // null: withheld from viewers (raw records are analyst-only)
    truncated: boolean;
    simulated: boolean;
    withheld: boolean;
  };
  source_name: string;
  alerts: { id: string; title: string; status: string; priority_band: Level }[];
}

export interface Asset {
  id: string;
  hostname: string;
  ip_addresses: string[];
  asset_type: string;
  environment: string;
  criticality: Level;
  owner: string | null;
  description: string | null;
  tags: string[];
  status: "active" | "retired";
  created_at: string;
  updated_at: string;
}

export interface Identity {
  id: string;
  username: string;
  display_name: string | null;
  department: string | null;
  title: string | null;
  privilege_level: "standard" | "privileged" | "service";
  status: "active" | "disabled";
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface WithActivity {
  open_alerts: number;
  last_seen_at: string | null;
}

export interface ContextActivity {
  open_alerts: number;
  total_alerts: number;
  open_incidents: number;
  total_incidents: number;
  last_seen_at: string | null;
  recent_alerts: AlertSummary[];
  incidents: IncidentSummary[];
}

export interface RuleSummary {
  rule_id: string;
  name: string;
  category: string;
  kind: string;
  severity: Level;
  confidence: "low" | "medium" | "high";
  enabled: boolean;
  in_library: boolean;
  version: number;
  techniques: string[];
  match_count: number;
  error_count: number;
  last_run_at: string | null;
  last_match_at: string | null;
}

export interface RuleDetail extends RuleSummary {
  description: string;
  definition: Record<string, unknown>;
  overrides: Record<string, unknown>;
  tunable: {
    threshold: { min: number; max: number } | null;
    time_window: { min: string; max: string } | null;
    severity: boolean;
    confidence: boolean;
    enabled: boolean;
    exclusions: boolean;
  };
  mitre: {
    technique_id: string;
    name: string;
    tactics: string[];
    url: string;
    reason: string;
    indicator: string | null;
  }[];
}

export interface RuleVersion {
  version: number;
  source: "library" | "admin";
  changed_by: string | null;
  change_reason: string | null;
  overrides: Record<string, unknown>;
  definition: Record<string, unknown>;
  created_at: string;
}

export interface DashboardSummary {
  generated_at: string;
  records_processed: number;
  events_stored: number;
  events_today: number;
  alerts_today: number;
  open_alerts: number;
  open_alerts_simulated: number;
  critical_alerts: number;
  high_alerts: number;
  severity_distribution: { severity: Level; count: number }[];
  open_incidents: number;
  incidents_under_investigation: number;
  monitored_hosts: number;
  inventory_assets: number;
  active_rules: number;
  library_rules: number;
  top_rules: { rule_id: string; name: string; alerts: number }[];
  top_source_ips: { source_ip: string; alerts: number }[];
  recent_alerts: AlertSummary[];
  recent_incidents: IncidentSummary[];
}

export interface TrendDay {
  day: string;
  alerts: Record<Level, number>;
  incidents: number;
  events: number;
}

// ---------- Phase 11: context, detection metrics, implemented coverage ----------

export interface InventoryContext {
  assets: Asset[];
  identities: (Identity & { roles: ("actor" | "target")[] })[];
  unknown_hosts: string[];
  unknown_accounts: string[];
}

export interface RuleMetrics {
  rule_id: string;
  name: string;
  category: string;
  severity: Level;
  enabled: boolean;
  in_library: boolean;
  alerts: number;
  open: number;
  confirmed: number;
  benign: number;
  false_positives: number;
  closed: number;
  false_positive_rate: number | null;
  median_triage_seconds: number | null;
  median_resolve_seconds: number | null;
  match_count: number;
  last_match_at: string | null;
}

export interface DetectionMetrics {
  days: number;
  from: string;
  to: string;
  items: RuleMetrics[];
}

export interface CoverageRule {
  rule_id: string;
  name: string;
  category: string;
  severity: Level;
  enabled: boolean;
  indicator: string | null;
  reason: string;
  alerts: number;
  last_triggered_at: string | null;
}

export interface CoverageTechnique {
  technique_id: string;
  name: string;
  url: string;
  tactics: string[];
  active: boolean;
  alerts: number;
  last_triggered_at: string | null;
  rules: CoverageRule[];
}

export interface Coverage {
  label: string;
  attack_version: string;
  checked_on: string;
  days: number;
  from: string;
  to: string;
  summary: {
    tactics_total: number;
    tactics_covered: number;
    techniques_covered: number;
    rules_in_library: number;
    rules_enabled: number;
    categories: Record<string, number>;
  };
  tactics: { id: string; name: string; url: string; techniques: string[]; active: boolean }[];
  techniques: CoverageTechnique[];
}

// ---------- Phase 12: detection playground, grouped queue ----------

export interface PlaygroundLine {
  line: number;
  status: "parsed" | "skipped" | "failed";
  code: string | null;
  timestamp: string | null;
  event: string | null;
  host: string | null;
  username: string | null;
  target_username: string | null;
  source_ip: string | null;
  process_name: string | null;
  excluded: boolean;
  matched: boolean | null;
  steps: string[];
  evidence: boolean;
}

export interface PlaygroundDetection {
  explanation: string;
  severity: Level;
  confidence: "low" | "medium" | "high";
  indicator: string | null;
  event_count: number;
  first_seen: string;
  last_seen: string;
  evidence_lines: number[];
  group: Record<string, unknown>;
  mitre: string[];
  investigation: string[];
  response: string[];
}

export interface PlaygroundResult {
  triggered: boolean;
  rule: {
    rule_id: string;
    name: string;
    kind: string;
    version: number;
    severity: Level;
    confidence: string;
    threshold: number | null;
    time_window: string | null;
    tried: Record<string, unknown>;
  };
  summary: {
    lines: number;
    parsed: number;
    skipped: number;
    failed: number;
    excluded: number;
    matched: number;
    detections: number;
  };
  detections: PlaygroundDetection[];
  lines: PlaygroundLine[];
}

export interface AlertGroup {
  key: string;
  label: string;
  alerts: number;
  open: number;
  top_priority: number;
  top_band: Level;
  last_event_at: string;
}
