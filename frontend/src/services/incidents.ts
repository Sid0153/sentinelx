import type {
  CorrelationSettings,
  EvidenceTag,
  IncidentDetail,
  IncidentDisposition,
  IncidentStatus,
  IncidentSummary,
  NotePublic,
  Page,
  TimelinePage,
  UserRef,
} from "../types/api";
import { apiRequest } from "./http";

export interface IncidentQuery {
  status: IncidentStatus[];
  assigned?: "me" | "unassigned";
  sort: "risk" | "recent";
  offset: number;
  limit: number;
}

const path = (id: string) => `/incidents/${encodeURIComponent(id)}`;

export function listIncidents(query: IncidentQuery, signal?: AbortSignal) {
  return apiRequest<Page<IncidentSummary>>("/incidents", {
    query: { ...query, assigned: query.assigned || undefined },
    signal,
  });
}

export function getIncident(id: string, signal?: AbortSignal) {
  return apiRequest<IncidentDetail>(path(id), { signal });
}

export function getTimeline(id: string, cursor: string | null, limit: number, signal?: AbortSignal) {
  return apiRequest<TimelinePage>(`${path(id)}/timeline`, {
    query: { limit, cursor: cursor ?? undefined },
    signal,
  });
}

export function listAssignees(signal?: AbortSignal) {
  return apiRequest<UserRef[]>("/incidents/assignees", { signal });
}

export function transitionIncident(
  id: string,
  change: {
    status: IncidentStatus;
    disposition?: IncidentDisposition;
    resolution?: string;
    reason?: string;
  },
) {
  return apiRequest<IncidentDetail>(`${path(id)}/transition`, { method: "POST", body: change });
}

export function assignIncident(id: string, assigneeId: string | null) {
  return apiRequest<IncidentDetail>(`${path(id)}/assign`, {
    method: "POST",
    body: { assignee_id: assigneeId },
  });
}

export function addNote(id: string, body: string) {
  return apiRequest<NotePublic>(`${path(id)}/notes`, { method: "POST", body: { body } });
}

export function changeEvidence(
  id: string,
  change: {
    event_id?: string;
    alert_id?: string;
    action: "PIN" | "UNPIN";
    tag?: EvidenceTag;
    comment?: string;
  },
) {
  return apiRequest<IncidentDetail>(`${path(id)}/evidence`, { method: "POST", body: change });
}

export function unlinkAlert(id: string, alertId: string, reason: string) {
  return apiRequest<IncidentDetail>(
    `${path(id)}/alerts/${encodeURIComponent(alertId)}/unlink`,
    { method: "POST", body: { reason } },
  );
}

export function renameIncident(id: string, title: string) {
  return apiRequest<IncidentDetail>(path(id), { method: "PATCH", body: { title } });
}

export function escalateAlert(alertId: string, reason: string) {
  return apiRequest<IncidentDetail>(`/alerts/${encodeURIComponent(alertId)}/escalate`, {
    method: "POST",
    body: { reason },
  });
}

export function getCorrelationSettings(signal?: AbortSignal) {
  return apiRequest<CorrelationSettings>("/settings", { signal });
}

export function updateCorrelationSettings(changes: Partial<CorrelationSettings>) {
  return apiRequest<CorrelationSettings>("/settings", { method: "PATCH", body: changes });
}
