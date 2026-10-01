import type { AuditEntry, AuditIntegrity, AuditResult, Page, Role, User } from "../types/api";
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

/** A temporary password, shown once; the user must change it at next sign-in. */
export function resetPassword(id: string): Promise<{ temporary_password: string }> {
  return apiRequest<{ temporary_password: string }>(
    `/users/${encodeURIComponent(id)}/reset-password`,
    { method: "POST" },
  );
}

export function resetMfa(id: string): Promise<User> {
  return apiRequest<User>(`/users/${encodeURIComponent(id)}/reset-mfa`, { method: "POST" });
}

export function auditIntegrity(signal?: AbortSignal): Promise<AuditIntegrity> {
  return apiRequest<AuditIntegrity>("/audit/integrity", { signal });
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
