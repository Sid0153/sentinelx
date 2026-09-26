import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

import { ErrorMessage, Field, formatUtc, PageHeader, Pagination, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listAudit } from "../services/admin";
import type { AuditEntry, AuditResult } from "../types/api";

const PAGE_SIZE = 50;

// Mirrors backend/app/audit/events.py. Later phases add their own actions.
const ACTIONS = [
  "LOGIN_SUCCEEDED",
  "LOGIN_FAILED",
  "LOGIN_RATE_LIMITED",
  "ACCOUNT_LOCKED",
  "LOGOUT",
  "PASSWORD_CHANGED",
  "REFRESH_TOKEN_REUSED",
  "ACCESS_DENIED",
  "USER_CREATED",
  "USER_ROLE_CHANGED",
  "USER_DEACTIVATED",
  "USER_REACTIVATED",
  "ASSET_CREATED",
  "ASSET_UPDATED",
  "IDENTITY_CREATED",
  "IDENTITY_UPDATED",
  "SOURCE_CREATED",
  "SOURCE_UPDATED",
  "INGEST_REJECTED",
  "RULE_ADDED",
  "RULE_LIBRARY_UPDATED",
  "RULE_RETIRED",
  "RULE_UPDATED",
  "DETECTION_RUN_REQUESTED",
  "ALERT_STATUS_CHANGED",
];
const RESULTS: AuditResult[] = ["SUCCESS", "FAILURE", "DENIED"];

const RESULT_STYLE: Record<AuditResult, string> = {
  SUCCESS: "text-emerald-300",
  FAILURE: "text-amber-300",
  DENIED: "text-rose-300",
};

/** Details as plain "key: value" text. Values are rendered as text, never as HTML. */
function formatDetails(details: Record<string, unknown>): string {
  return Object.entries(details)
    .map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`)
    .join(" · ");
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  return (
    <tr className="border-t border-slate-800 align-top">
      <td className="whitespace-nowrap py-2 pr-4 font-mono text-xs text-slate-400">
        {formatUtc(entry.occurred_at)}
      </td>
      <td className="py-2 pr-4 font-mono text-xs text-slate-100">{entry.action}</td>
      <td className={`py-2 pr-4 text-xs font-medium ${RESULT_STYLE[entry.result]}`}>{entry.result}</td>
      <td className="py-2 pr-4 text-slate-300">{entry.actor_label ?? "anonymous"}</td>
      <td className="py-2 pr-4 font-mono text-xs text-slate-400">{entry.client_ip ?? "—"}</td>
      <td className="py-2 text-xs text-slate-400">{formatDetails(entry.details)}</td>
    </tr>
  );
}

export function AuditPage() {
  // Filters live in the URL, so a filtered view can be bookmarked and shared.
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const result = (params.get("result") ?? "") as AuditResult | "";
  const offset = Number(params.get("offset") ?? "0") || 0;

  const load = useCallback(
    (signal: AbortSignal) =>
      listAudit({ action, result: result || undefined, offset, limit: PAGE_SIZE }, signal),
    [action, result, offset],
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
        title="Audit log"
        description="Append-only record of security-relevant actions. Entries cannot be edited or deleted, by anyone."
      />
      <div className="mb-3 flex flex-wrap gap-3">
        <Field label="Action">
          <select value={action} onChange={(e) => setFilter("action", e.target.value)} className={selectClass}>
            <option value="">All actions</option>
            {ACTIONS.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </Field>
        <Field label="Result">
          <select value={result} onChange={(e) => setFilter("result", e.target.value)} className={selectClass}>
            <option value="">All results</option>
            {RESULTS.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </Field>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 px-4">
        {error ? (
          <div className="py-3">
            <ErrorMessage>{error.message}</ErrorMessage>
          </div>
        ) : !data ? (
          <p className="py-3 text-sm text-slate-400">Loading audit log…</p>
        ) : data.items.length === 0 ? (
          <p className="py-3 text-sm text-slate-400">No entries match these filters.</p>
        ) : (
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Time</th>
                <th className="py-2 pr-4 font-medium">Action</th>
                <th className="py-2 pr-4 font-medium">Result</th>
                <th className="py-2 pr-4 font-medium">Actor</th>
                <th className="py-2 pr-4 font-medium">Client IP</th>
                <th className="py-2 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((entry) => (
                <AuditRow key={entry.id} entry={entry} />
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
