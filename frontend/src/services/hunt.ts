import type {
  HuntDefinition,
  HuntFields,
  HuntFilter,
  HuntQuery,
  HuntResult,
  SavedHunt,
  TemplateInfo,
  TemplateResult,
  TimeRange,
} from "../types/hunt";
import { apiRequest } from "./http";

export function getHuntFields(signal?: AbortSignal) {
  return apiRequest<HuntFields>("/hunt/fields", { signal });
}

export function runHunt(query: HuntQuery, cursor: string | null, signal?: AbortSignal) {
  return apiRequest<HuntResult>("/hunt/query", {
    method: "POST",
    body: { ...query, cursor },
    signal,
  });
}

export function listTemplates(signal?: AbortSignal) {
  return apiRequest<TemplateInfo[]>("/hunt/templates", { signal });
}

export function runTemplate(
  id: string,
  params: Record<string, number>,
  timeRange: TimeRange,
  signal?: AbortSignal,
) {
  return apiRequest<TemplateResult>(`/hunt/templates/${encodeURIComponent(id)}/run`, {
    method: "POST",
    body: { params, time_range: timeRange },
    signal,
  });
}

export function listSavedHunts(signal?: AbortSignal) {
  return apiRequest<SavedHunt[]>("/hunt/saved", { signal });
}

export function saveHunt(body: {
  name: string;
  description: string | null;
  definition: HuntDefinition;
  shared: boolean;
}) {
  return apiRequest<SavedHunt>("/hunt/saved", { method: "POST", body });
}

export function updateSavedHunt(id: string, changes: Partial<Pick<SavedHunt, "name" | "shared">>) {
  return apiRequest<SavedHunt>(`/hunt/saved/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: changes,
  });
}

export function deleteSavedHunt(id: string) {
  return apiRequest<void>(`/hunt/saved/${encodeURIComponent(id)}`, { method: "DELETE" });
}

// ---------- the hunt in the URL ----------
// The whole hunt is one `q` parameter holding the same JSON as a saved hunt's definition, so
// a hunt can be bookmarked, shared, saved, and opened from a pivot link elsewhere in the app.

export function huntUrl(definition: HuntDefinition): string {
  return `/hunt?q=${encodeURIComponent(JSON.stringify(definition))}`;
}

export function parseHunt(q: string | null): HuntDefinition | null {
  if (!q) return null;
  try {
    const value = JSON.parse(q) as HuntDefinition;
    if (value && (value.kind === "query" || value.kind === "template")) return value;
  } catch {
    // An edited or truncated link: start a new hunt instead of failing.
  }
  return null;
}

const DAY = 24 * 3600 * 1000;

/** A pivot: events where `field` equals `value`, around a moment (an alert's or incident's
 * activity) or over the last 24 hours. The backend bounds a range to 31 days. */
export function pivotUrl(
  filters: HuntFilter[],
  around?: { from: string; to: string },
): string {
  let timeRange: TimeRange = { last: "24h" };
  if (around) {
    const from = Date.parse(around.from) - 3600 * 1000;
    const to = Math.min(Date.parse(around.to) + 3600 * 1000, from + 31 * DAY);
    timeRange = { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
  }
  return huntUrl({ kind: "query", query: { time_range: timeRange, filters } });
}

export function eq(field: string, value: string): HuntFilter {
  return { field, op: "eq", value };
}
