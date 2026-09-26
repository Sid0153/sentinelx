import type { IncidentStatus, LinkedAlert } from "../types/api";

export const INCIDENT_STATUS_LABEL: Record<IncidentStatus, string> = {
  OPEN: "Open",
  TRIAGED: "Triaged",
  INVESTIGATING: "Investigating",
  CONTAINED: "Contained",
  RESOLVED: "Resolved",
  CLOSED: "Closed",
};

const STATUS_STYLE: Record<IncidentStatus, string> = {
  OPEN: "text-sky-300",
  TRIAGED: "text-violet-300",
  INVESTIGATING: "text-amber-300",
  CONTAINED: "text-orange-300",
  RESOLVED: "text-emerald-300",
  CLOSED: "text-slate-400",
};

export function IncidentStatusText({ status }: { status: IncidentStatus }) {
  return (
    <span className={`text-xs font-medium ${STATUS_STYLE[status]}`}>
      {INCIDENT_STATUS_LABEL[status]}
    </span>
  );
}

const STRENGTH_STYLE: Record<LinkedAlert["link_strength"], string> = {
  ORIGIN: "border-sky-800 text-sky-200",
  STRONG: "border-emerald-800 text-emerald-200",
  MEDIUM: "border-amber-800 text-amber-200",
  WEAK: "border-slate-700 text-slate-300",
  MANUAL: "border-violet-800 text-violet-200",
};

const STRENGTH_LABEL: Record<LinkedAlert["link_strength"], string> = {
  ORIGIN: "opened it",
  STRONG: "strong link",
  MEDIUM: "medium link",
  WEAK: "weak link",
  MANUAL: "added by hand",
};

export function StrengthBadge({ strength }: { strength: LinkedAlert["link_strength"] }) {
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[11px] ${STRENGTH_STYLE[strength]}`}>
      {STRENGTH_LABEL[strength]}
    </span>
  );
}

export function incidentRef(number: number): string {
  return `INC-${number}`;
}

/** "a, b, c and 17 more": long entity lists (a campaign can have many sources) stay readable. */
export function shortList(values: string[], shown = 3): string {
  if (values.length <= shown) return values.join(", ");
  return `${values.slice(0, shown).join(", ")} and ${values.length - shown} more`;
}
