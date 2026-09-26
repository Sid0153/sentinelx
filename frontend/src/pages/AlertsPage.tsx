import { useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { PriorityBadge, SimulatedTag, StatusText } from "../components/alerts";
import { ErrorMessage, Field, PageHeader, Pagination, formatUtc, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listAlerts } from "../services/alerts";
import type { AlertStatus, AlertSummary } from "../types/api";

const PAGE_SIZE = 50;

// Queue views: which statuses each one shows.
const VIEWS: Record<string, { label: string; statuses: AlertStatus[] }> = {
  open: { label: "Open", statuses: ["NEW", "TRIAGED", "IN_PROGRESS"] },
  new: { label: "New only", statuses: ["NEW"] },
  resolved: { label: "Resolved", statuses: ["RESOLVED"] },
  false_positive: { label: "False positives", statuses: ["FALSE_POSITIVE"] },
  all: { label: "All", statuses: [] },
};

const SEVERITIES = ["critical", "high", "medium", "low"];

function Entities({ alert }: { alert: AlertSummary }) {
  const parts = [
    alert.host && `host ${alert.host}`,
    alert.username && `user ${alert.username}`,
    alert.source_ip && `from ${alert.source_ip}`,
  ].filter(Boolean);
  return <span className="text-xs text-slate-400">{parts.join(" · ") || "—"}</span>;
}

function AlertRow({ alert }: { alert: AlertSummary }) {
  return (
    <tr className="border-t border-slate-800 align-top">
      <td className="py-2 pr-4">
        <PriorityBadge score={alert.priority_score} band={alert.priority_band} />
      </td>
      <td className="py-2 pr-4">
        <Link to={`/alerts/${alert.id}`} className="text-slate-100 hover:text-sky-300">
          {alert.title}
        </Link>
        <div className="mt-0.5 flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-slate-500">{alert.rule_id}</span>
          <Entities alert={alert} />
          {alert.simulated && <SimulatedTag />}
        </div>
      </td>
      <td className="py-2 pr-4">
        <StatusText status={alert.status} />
      </td>
      <td className="py-2 pr-4 text-right font-mono text-xs text-slate-300">
        {alert.event_count}
        {alert.evidence_truncated && "+"}
      </td>
      <td className="whitespace-nowrap py-2 font-mono text-xs text-slate-400">
        {formatUtc(alert.last_event_at)}
      </td>
    </tr>
  );
}

export function AlertsPage() {
  // Filters live in the URL, so a queue view can be bookmarked and shared.
  const [params, setParams] = useSearchParams();
  const view = params.get("view") ?? "open";
  const severity = params.get("severity") ?? "";
  const sort = params.get("sort") === "recent" ? "recent" : "priority";
  const offset = Number(params.get("offset") ?? "0") || 0;
  const statuses = (VIEWS[view] ?? VIEWS.open).statuses;

  const load = useCallback(
    (signal: AbortSignal) =>
      listAlerts({ status: statuses, severity, sort, offset, limit: PAGE_SIZE }, signal),
    [statuses, severity, sort, offset],
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
        title="Alerts"
        description="Ordered by the SentinelX priority score (severity, confidence, asset and identity context, evidence volume). Open each alert to see how its score adds up."
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
        <Field label="Severity">
          <select value={severity} onChange={(e) => setFilter("severity", e.target.value)} className={selectClass}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
        <Field label="Order">
          <select value={sort} onChange={(e) => setFilter("sort", e.target.value)} className={selectClass}>
            <option value="priority">Priority</option>
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
          <p className="py-3 text-sm text-slate-400">Loading alerts…</p>
        ) : data.items.length === 0 ? (
          <p className="py-3 text-sm text-slate-400">
            {view === "open"
              ? "No open alerts. Alerts appear when detection rules match ingested events."
              : "No alerts match these filters."}
          </p>
        ) : (
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Priority</th>
                <th className="py-2 pr-4 font-medium">Alert</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 text-right font-medium">Events</th>
                <th className="py-2 font-medium">Last activity</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((alert) => (
                <AlertRow key={alert.id} alert={alert} />
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
