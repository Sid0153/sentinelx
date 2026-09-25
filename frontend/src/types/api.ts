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
