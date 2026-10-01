import type { Page } from "../types/api";
import type {
  Asset,
  ContextActivity,
  Coverage,
  DashboardSummary,
  DetectionMetrics,
  EventDetail,
  EventPage,
  Identity,
  RuleDetail,
  RuleSummary,
  RuleVersion,
  TrendDay,
  WithActivity,
} from "../types/inventory";
import { apiRequest } from "./http";

// ---------- dashboard ----------

export function getDashboard(signal?: AbortSignal) {
  return apiRequest<DashboardSummary>("/dashboard/summary", { signal });
}

export function getTrends(days: number, signal?: AbortSignal) {
  return apiRequest<{ days: number; items: TrendDay[] }>("/dashboard/trends", {
    query: { days },
    signal,
  });
}

// ---------- events ----------

export interface EventQuery {
  from?: string;
  to?: string;
  category?: string;
  outcome?: string;
  host?: string;
  username?: string;
  source_ip?: string;
  cursor?: string;
  limit: number;
}

export function listEvents(query: EventQuery, signal?: AbortSignal) {
  return apiRequest<EventPage>("/events", { query: { ...query }, signal });
}

export function getEvent(id: string, signal?: AbortSignal) {
  return apiRequest<EventDetail>(`/events/${encodeURIComponent(id)}`, { signal });
}

// ---------- assets and identities ----------

export interface InventoryQuery {
  search?: string;
  criticality?: string;
  environment?: string;
  privilege_level?: string;
  status?: string;
  offset: number;
  limit: number;
}

export function listAssets(query: InventoryQuery, signal?: AbortSignal) {
  return apiRequest<Page<Asset & WithActivity>>("/assets", { query: { ...query }, signal });
}

export function getAsset(id: string, signal?: AbortSignal) {
  return apiRequest<Asset>(`/assets/${encodeURIComponent(id)}`, { signal });
}

export function getAssetActivity(id: string, signal?: AbortSignal) {
  return apiRequest<ContextActivity>(`/assets/${encodeURIComponent(id)}/activity`, { signal });
}

export function saveAsset(id: string | null, body: Record<string, unknown>) {
  return id
    ? apiRequest<Asset>(`/assets/${encodeURIComponent(id)}`, { method: "PATCH", body })
    : apiRequest<Asset>("/assets", { method: "POST", body });
}

export function listIdentities(query: InventoryQuery, signal?: AbortSignal) {
  return apiRequest<Page<Identity & WithActivity>>("/identities", {
    query: { ...query },
    signal,
  });
}

export function getIdentity(id: string, signal?: AbortSignal) {
  return apiRequest<Identity>(`/identities/${encodeURIComponent(id)}`, { signal });
}

export function getIdentityActivity(id: string, signal?: AbortSignal) {
  return apiRequest<ContextActivity>(`/identities/${encodeURIComponent(id)}/activity`, {
    signal,
  });
}

export function saveIdentity(id: string | null, body: Record<string, unknown>) {
  return id
    ? apiRequest<Identity>(`/identities/${encodeURIComponent(id)}`, { method: "PATCH", body })
    : apiRequest<Identity>("/identities", { method: "POST", body });
}

// ---------- detection rules ----------

export function listRules(signal?: AbortSignal) {
  return apiRequest<RuleSummary[]>("/detections", { signal });
}

export function getRule(ruleId: string, signal?: AbortSignal) {
  return apiRequest<RuleDetail>(`/detections/${encodeURIComponent(ruleId)}`, { signal });
}

export function listRuleVersions(ruleId: string, signal?: AbortSignal) {
  return apiRequest<RuleVersion[]>(`/detections/${encodeURIComponent(ruleId)}/versions`, {
    signal,
  });
}

export function tuneRule(ruleId: string, changes: Record<string, unknown>) {
  return apiRequest<RuleDetail>(`/detections/${encodeURIComponent(ruleId)}`, {
    method: "PATCH",
    body: changes,
  });
}

// ---------- detection metrics and coverage ----------

export function getDetectionMetrics(days: number, signal?: AbortSignal) {
  return apiRequest<DetectionMetrics>("/detections/metrics", { query: { days }, signal });
}

export function getCoverage(days: number, signal?: AbortSignal) {
  return apiRequest<Coverage>("/mitre/coverage", { query: { days }, signal });
}
