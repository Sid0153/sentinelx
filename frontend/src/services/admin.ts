import type { AuditEntry, AuditResult, Page, Role, User } from "../types/api";
import { apiRequest } from "./http";

export function listUsers(offset: number, limit: number, signal?: AbortSignal) {
  return apiRequest<Page<User>>("/users", { query: { offset, limit }, signal });
}

export function createUser(email: string, password: string, role: Role): Promise<User> {
  return apiRequest<User>("/users", { method: "POST", body: { email, password, role } });
}

export function updateUser(
  id: string,
  changes: { role?: Role; is_active?: boolean },
): Promise<User> {
  return apiRequest<User>(`/users/${encodeURIComponent(id)}`, { method: "PATCH", body: changes });
}

export interface AuditQuery {
  action?: string;
  result?: AuditResult;
  offset: number;
  limit: number;
}

export function listAudit(query: AuditQuery, signal?: AbortSignal) {
  return apiRequest<Page<AuditEntry>>("/audit", {
    query: { ...query, action: query.action || undefined, result: query.result || undefined },
    signal,
  });
}
