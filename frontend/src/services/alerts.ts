import type {
  AlertDetail,
  AlertStatus,
  AlertSummary,
  EvidenceEvent,
  Page,
  TransitionRequest,
} from "../types/api";
import type { AlertGroup } from "../types/inventory";
import { apiRequest } from "./http";

export interface AlertQuery {
  status: AlertStatus[];
  severity?: string;
  rule_id?: string;
  host?: string;
  username?: string;
  source_ip?: string;
  sort: "priority" | "recent";
  offset: number;
  limit: number;
}

function filterQuery(query: Omit<AlertQuery, "offset" | "limit">) {
  return {
    status: query.status,
    severity: query.severity || undefined,
    rule_id: query.rule_id || undefined,
    host: query.host || undefined,
    username: query.username || undefined,
    source_ip: query.source_ip || undefined,
    sort: query.sort,
  };
}

export function listAlerts(query: AlertQuery, signal?: AbortSignal) {
  return apiRequest<Page<AlertSummary>>("/alerts", {
    query: { ...filterQuery(query), offset: query.offset, limit: query.limit },
    signal,
  });
}

export type GroupBy = "rule" | "host" | "username" | "source_ip";

/** The queue counted per rule, host, account or source, with the same filters. */
export function groupAlerts(
  query: Omit<AlertQuery, "offset" | "limit">,
  by: GroupBy,
  signal?: AbortSignal,
) {
  return apiRequest<{ by: GroupBy; total: number; items: AlertGroup[] }>("/alerts/groups", {
    query: { ...filterQuery(query), by },
    signal,
  });
}

export function getAlert(id: string, signal?: AbortSignal) {
  return apiRequest<AlertDetail>(`/alerts/${encodeURIComponent(id)}`, { signal });
}

export function listEvidence(id: string, offset: number, limit: number, signal?: AbortSignal) {
  return apiRequest<Page<EvidenceEvent>>(`/alerts/${encodeURIComponent(id)}/events`, {
    query: { offset, limit },
    signal,
  });
}

export function transitionAlert(id: string, change: TransitionRequest): Promise<AlertDetail> {
  return apiRequest<AlertDetail>(`/alerts/${encodeURIComponent(id)}/transition`, {
    method: "POST",
    body: change,
  });
}
