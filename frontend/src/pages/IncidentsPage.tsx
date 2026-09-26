import { useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { PriorityBadge, SimulatedTag } from "../components/alerts";
import { IncidentStatusText, incidentRef, shortList } from "../components/incidents";
import { ErrorMessage, Field, PageHeader, Pagination, formatUtc, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listIncidents } from "../services/incidents";
import type { IncidentStatus, IncidentSummary } from "../types/api";

const PAGE_SIZE = 50;

const VIEWS: Record<string, { label: string; statuses: IncidentStatus[] }> = {
  open: { label: "Open", statuses: ["OPEN", "TRIAGED", "INVESTIGATING", "CONTAINED"] },
  resolved: { label: "Resolved", statuses: ["RESOLVED"] },
  closed: { label: "Closed", statuses: ["CLOSED"] },
  all: { label: "All", statuses: [] },
};

function Scope({ incident }: { incident: IncidentSummary }) {
  const parts = [
    incident.hosts.length ? `hosts ${shortList(incident.hosts)}` : null,
    incident.usernames.length ? `accounts ${shortList(incident.usernames)}` : null,
    incident.source_ips.length ? `from ${shortList(incident.source_ips)}` : null,
  ].filter(Boolean);
  return <span className="text-xs text-slate-400">{parts.join(" · ") || "—"}</span>;
}

function IncidentRow({ incident }: { incident: IncidentSummary }) {
  return (
    <tr className="border-t border-slate-800 align-top">
      <td className="py-2 pr-4">
        <PriorityBadge score={incident.risk_score} band={incident.risk_band} />
      </td>
      <td className="py-2 pr-4">
        <Link to={`/incidents/${incident.id}`} className="text-slate-100 hover:text-sky-300">
          <span className="font-mono text-xs text-slate-500">{incidentRef(incident.number)}</span>{" "}
          {incident.title}
        </Link>
        <div className="mt-0.5 flex flex-wrap items-center gap-2">
          <Scope incident={incident} />
          {incident.simulated && <SimulatedTag />}
        </div>
      </td>
      <td className="py-2 pr-4">
        <IncidentStatusText status={incident.status} />
      </td>
      <td className="py-2 pr-4 text-right font-mono text-xs text-slate-300">{incident.alert_count}</td>
      <td className="py-2 pr-4 text-xs text-slate-300">{incident.assigned_to?.email ?? "—"}</td>
      <td className="whitespace-nowrap py-2 font-mono text-xs text-slate-400">
        {formatUtc(incident.last_activity_at)}
      </td>
    </tr>
  );
}

export function IncidentsPage() {
  const [params, setParams] = useSearchParams();
  const view = params.get("view") ?? "open";
  const assigned = params.get("assigned") as "me" | "unassigned" | null;
  const sort = params.get("sort") === "recent" ? "recent" : "risk";
  const offset = Number(params.get("offset") ?? "0") || 0;
  const statuses = (VIEWS[view] ?? VIEWS.open).statuses;

  const load = useCallback(
    (signal: AbortSignal) =>
      listIncidents(
        { status: statuses, assigned: assigned ?? undefined, sort, offset, limit: PAGE_SIZE },
        signal,
      ),
    [statuses, assigned, sort, offset],
  );
  const { data, error, loading } = useApi(load);

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("offset");
    setParams(next);
  }

  return (
    <section>
      <PageHeader
        title="Incidents"
        description="Related alerts grouped into one investigation. Each alert shows why it was linked. Ordered by risk: the highest alert priority plus bonuses for several kinds of finding and breadth."
      />
      <div className="mb-3 flex flex-wrap gap-3">
        <Field label="View">
          <select value={view} onChange={(e) => setFilter("view", e.target.value)} className={selectClass}>
            {Object.entries(VIEWS).map(([key, v]) => (
              <option key={key} value={key}>
                {v.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Assigned">
          <select
            value={assigned ?? ""}
            onChange={(e) => setFilter("assigned", e.target.value)}
            className={selectClass}
          >
            <option value="">Anyone</option>
            <option value="me">Me</option>
            <option value="unassigned">Nobody</option>
          </select>
        </Field>
        <Field label="Order">
          <select value={sort} onChange={(e) => setFilter("sort", e.target.value)} className={selectClass}>
            <option value="risk">Risk</option>
            <option value="recent">Most recent activity</option>
          </select>
        </Field>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 px-4">
        {error ? (
          <div className="py-3">
            <ErrorMessage>{error.message}</ErrorMessage>
          </div>
        ) : !data ? (
          <p className="py-3 text-sm text-slate-400">Loading incidents…</p>
        ) : data.items.length === 0 ? (
          <p className="py-3 text-sm text-slate-400">
            {view === "open"
              ? "No open incidents. Incidents open when a high-severity alert fires, or when related alerts add up to a multi-stage story."
              : "No incidents match these filters."}
          </p>
        ) : (
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Risk</th>
                <th className="py-2 pr-4 font-medium">Incident</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 text-right font-medium">Alerts</th>
                <th className="py-2 pr-4 font-medium">Assigned</th>
                <th className="py-2 font-medium">Last activity</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((incident) => (
                <IncidentRow key={incident.id} incident={incident} />
              ))}
            </tbody>
          </table>
        )}
      </div>
      {data && (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={(next) => {
            const updated = new URLSearchParams(params);
            updated.set("offset", String(next));
            setParams(updated);
          }}
        />
      )}
    </section>
  );
}
