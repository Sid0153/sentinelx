// Threat hunting (mirror backend/app/schemas/hunt.py and app/hunting/query.py).
import type { AlertStatus, Level } from "./api";
import type { EventRecord } from "./inventory";

export type HuntOperator =
  | "eq"
  | "ne"
  | "in"
  | "not_in"
  | "contains"
  | "startswith"
  | "endswith"
  | "cidr"
  | "exists"
  | "gt"
  | "gte"
  | "lt"
  | "lte";

export type FilterValue = string | number | boolean | (string | number)[] | null;

export interface HuntFilter {
  field: string;
  op: HuntOperator;
  value: FilterValue;
}

/** Relative (`last`: "24h") or absolute (`from`/`to`, ISO with a time zone). */
export interface TimeRange {
  last?: string;
  from?: string;
  to?: string;
}

export interface AlertContext {
  in_alert?: boolean | null;
  rule_ids?: string[];
  severities?: Level[];
  statuses?: AlertStatus[];
}

export interface HuntQuery {
  time_range: TimeRange;
  filters: HuntFilter[];
  alert?: AlertContext;
  sort?: "newest" | "oldest";
  limit?: number;
}

export interface QueryDefinition {
  kind: "query";
  query: HuntQuery;
}

export interface TemplateDefinition {
  kind: "template";
  template_id: string;
  params: Record<string, number>;
  time_range: TimeRange;
}

export type HuntDefinition = QueryDefinition | TemplateDefinition;

export interface HuntFieldInfo {
  field: string;
  kind: "text" | "ip" | "number" | "boolean";
  operators: HuntOperator[];
}

export interface HuntFields {
  fields: HuntFieldInfo[];
  attribute_operators: HuntOperator[];
  max_filters: number;
  max_range_days: number;
}

export interface HuntResult {
  items: EventRecord[];
  next_cursor: string | null;
  total: number;
  total_capped: boolean;
  from: string;
  to: string;
  limit: number;
}

export interface TemplateColumn {
  key: string;
  label: string;
  kind: "text" | "time" | "number" | "ip" | "host" | "user" | "process" | "event" | "list";
}

export interface TemplateInfo {
  id: string;
  name: string;
  question: string;
  technique: string;
  mirrors_rule: string | null;
  params: { name: string; description: string; default: number; minimum: number; maximum: number }[];
  columns: TemplateColumn[];
}

export interface TemplateResult {
  template_id: string;
  columns: TemplateColumn[];
  rows: Record<string, unknown>[];
  truncated: boolean;
  from: string;
  to: string;
}

export interface SavedHunt {
  id: string;
  name: string;
  description: string | null;
  kind: "query" | "template";
  definition: HuntDefinition;
  shared: boolean;
  owner_id: string;
  owner_email: string | null;
  is_owner: boolean;
  valid: boolean;
  problem: string | null;
  created_at: string;
  updated_at: string;
}
