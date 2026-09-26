import type {
  AlertDetail,
  AlertStatus,
  AlertSummary,
  EvidenceEvent,
  Page,
  TransitionRequest,
} from "../types/api";
import { apiRequest } from "./http";

export interface AlertQuery {
  status: AlertStatus[];
  severity?: string;
  sort: "priority" | "recent";
  offset: number;
  limit: number;
}

export function listAlerts(query: AlertQuery, signal?: AbortSignal) {
  return apiRequest<Page<AlertSummary>>("/alerts", {
    query: {
      status: query.status,
      severity: query.severity || undefined,
      sort: query.sort,
      offset: query.offset,
      limit: query.limit,
    },
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
