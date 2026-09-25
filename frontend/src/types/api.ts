// Mirrors the backend response schemas (backend/app/api/*). Keep in sync with docs/openapi.json.

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string | null;
    details?: { loc: (string | number)[]; msg: string; type: string }[];
  };
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
