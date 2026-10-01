import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { SimulatedTag } from "../components/alerts";
import {
  Button,
  ErrorMessage,
  Field,
  PageHeader,
  formatUtc,
  inputClass,
  selectClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listEvents } from "../services/inventory";
import type { EventRecord } from "../types/inventory";

const PAGE_SIZE = 50;
const RANGES: Record<string, { label: string; hours: number }> = {
  "1h": { label: "Last hour", hours: 1 },
  "24h": { label: "Last 24 hours", hours: 24 },
  "7d": { label: "Last 7 days", hours: 24 * 7 },
  "31d": { label: "Last 31 days", hours: 24 * 31 },
};
const CATEGORIES = ["authentication", "iam", "privilege", "process", "network", "web", "application"];
const TEXT_FILTERS = [
  { key: "host", label: "Host" },
  { key: "username", label: "User" },
  { key: "source_ip", label: "Source address" },
] as const;

function Who({ event }: { event: EventRecord }) {
  const parts = [
    event.username && `user ${event.username}`,
    event.target_username && `→ ${event.target_username}`,
    event.source_ip && `from ${event.source_ip}${event.source_ip_scope ? ` (${event.source_ip_scope})` : ""}`,
    event.destination_ip && `to ${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}`,
  ].filter(Boolean);
  return <span className="text-xs text-slate-400">{parts.join(" · ") || "—"}</span>;
}

export function EventsPage() {
  // Filters live in the URL, so a view can be shared; paging (keyset cursors) does not.
  const [params, setParams] = useSearchParams();
  const range = RANGES[params.get("range") ?? ""] ? (params.get("range") as string) : "24h";
  const category = params.get("category") ?? "";
  const outcome = params.get("outcome") ?? "";
  const text = Object.fromEntries(TEXT_FILTERS.map((f) => [f.key, params.get(f.key) ?? ""]));
  const [draft, setDraft] = useState(text);
  const filterKey = params.toString();
  // Cursors belong to the filters they were issued for: a new filter starts again from the
  // newest page in the same render (never one request with a stale cursor).
  const [paging, setPaging] = useState({ key: filterKey, cursors: [undefined] as (string | undefined)[] });
  const cursors = paging.key === filterKey ? paging.cursors : [undefined];
  const setCursors = (next: (string | undefined)[]) => setPaging({ key: filterKey, cursors: next });

  // Back/forward or a link can change the URL: the text boxes follow it.
  useEffect(() => {
    setDraft(Object.fromEntries(TEXT_FILTERS.map((f) => [f.key, params.get(f.key) ?? ""])));
  }, [filterKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const window = useMemo(() => {
    const to = new Date();
    const from = new Date(to.getTime() - RANGES[range].hours * 3600 * 1000);
    return { from: from.toISOString(), to: to.toISOString() };
  }, [range, filterKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const cursor = cursors[cursors.length - 1];
  const load = useCallback(
    (signal: AbortSignal) =>
      listEvents(
        {
          ...window,
          category: category || undefined,
          outcome: outcome || undefined,
          host: text.host || undefined,
          username: text.username || undefined,
          source_ip: text.source_ip || undefined,
          cursor,
          limit: PAGE_SIZE,
        },
        signal,
      ),
    // text values come from the URL (filterKey)
    [window, category, outcome, cursor, filterKey], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const { data, error, loading } = useApi(load);

  function setFilter(changes: Record<string, string>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value.trim()) next.set(key, value.trim());
      else next.delete(key);
    }
    setParams(next);
  }

  return (
    <section>
      <PageHeader
        title="Events"
        description="Normalized events, newest first, from every log source. Open one to see the raw record it came from and the alerts that cite it. Times are UTC."
      />
      <form
        aria-label="Event filters"
        className="mb-3 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setFilter(draft);
        }}
      >
        <Field label="Time range">
          <select value={range} onChange={(e) => setFilter({ range: e.target.value })} className={selectClass}>
            {Object.entries(RANGES).map(([key, r]) => (
              <option key={key} value={key}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Category">
          <select value={category} onChange={(e) => setFilter({ category: e.target.value })} className={selectClass}>
            <option value="">All</option>
            {CATEGORIES.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </Field>
        <Field label="Outcome">
          <select value={outcome} onChange={(e) => setFilter({ outcome: e.target.value })} className={selectClass}>
            <option value="">All</option>
            <option>success</option>
            <option>failure</option>
            <option>unknown</option>
          </select>
        </Field>
        {TEXT_FILTERS.map((f) => (
          <Field key={f.key} label={f.label}>
            <input
              value={draft[f.key]}
              onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
              className={`${inputClass} w-40`}
              maxLength={253}
            />
          </Field>
        ))}
        <Button type="submit">Apply</Button>
      </form>

      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 px-4">
        {error ? (
          <div className="py-3">
            <ErrorMessage>{error.message}</ErrorMessage>
          </div>
        ) : !data ? (
          <p className="py-3 text-sm text-slate-400">Loading events…</p>
        ) : data.items.length === 0 ? (
          <p className="py-3 text-sm text-slate-400">
            No events match these filters in this time range.
          </p>
        ) : (
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Time</th>
                <th className="py-2 pr-4 font-medium">Event</th>
                <th className="py-2 pr-4 font-medium">Host</th>
                <th className="py-2 font-medium">Who</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((event) => (
                <tr key={event.id} className="border-t border-slate-800 align-top">
                  <td className="whitespace-nowrap py-1.5 pr-4 font-mono text-xs text-slate-400">
                    <Link to={`/events/${event.id}`} className="hover:text-sky-300">
                      {formatUtc(event.timestamp)}
                    </Link>
                  </td>
                  <td className="py-1.5 pr-4">
                    <Link to={`/events/${event.id}`} className="font-mono text-xs text-slate-100 hover:text-sky-300">
                      {event.event_category}/{event.event_action}{" "}
                      <span className={event.event_outcome === "failure" ? "text-amber-300" : ""}>
                        {event.event_outcome}
                      </span>
                    </Link>
                    {event.simulated && (
                      <span className="ml-2">
                        <SimulatedTag />
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 pr-4 text-xs text-slate-300">{event.host ?? "—"}</td>
                  <td className="py-1.5">
                    <Who event={event} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {data && (
        <nav aria-label="Pagination" className="mt-3 flex items-center justify-between text-sm">
          <span className="text-slate-400">
            Page {cursors.length} · {data.items.length} events
          </span>
          <span className="flex gap-2">
            <Button
              variant="secondary"
              disabled={cursors.length === 1}
              onClick={() => setCursors(cursors.slice(0, -1))}
            >
              Newer
            </Button>
            <Button
              variant="secondary"
              disabled={!data.next_cursor}
              onClick={() => setCursors([...cursors, data.next_cursor ?? undefined])}
            >
              Older
            </Button>
          </span>
        </nav>
      )}
    </section>
  );
}
