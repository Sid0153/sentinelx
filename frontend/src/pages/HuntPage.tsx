import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import { SimulatedTag } from "../components/alerts";
import {
  FilterRowEditor,
  HuntError,
  PivotValue,
  TimeRangeEditor,
  filterFromRow,
  rowFromFilter,
  type FilterRow,
} from "../components/hunt";
import { Button, ErrorMessage, Field, PageHeader, Panel, formatUtc, inputClass, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/http";
import {
  deleteSavedHunt,
  getHuntFields,
  huntUrl,
  listSavedHunts,
  listTemplates,
  parseHunt,
  runHunt,
  runTemplate,
  saveHunt,
  updateSavedHunt,
} from "../services/hunt";
import type { AlertStatus, Level } from "../types/api";
import type {
  AlertContext,
  HuntDefinition,
  HuntFields,
  HuntFilter,
  QueryDefinition,
  SavedHunt,
  TemplateColumn,
  TemplateDefinition,
  TemplateInfo,
} from "../types/hunt";

const NEW_HUNT: QueryDefinition = { kind: "query", query: { time_range: { last: "24h" }, filters: [] } };
const PAGE_SIZE = 50;
const SEVERITIES: Level[] = ["critical", "high", "medium", "low"];
const STATUSES: AlertStatus[] = ["NEW", "TRIAGED", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"];

function describeRange(definition: HuntDefinition): string {
  const range = definition.kind === "query" ? definition.query.time_range : definition.time_range;
  return range.last ? `last ${range.last}` : `${formatUtc(range.from ?? "")} – ${formatUtc(range.to ?? "")}`;
}

function hasAlertFilters(alert?: AlertContext): boolean {
  if (!alert) return false;
  return (
    alert.in_alert != null ||
    (alert.rule_ids ?? []).length > 0 ||
    (alert.severities ?? []).length > 0 ||
    (alert.statuses ?? []).length > 0
  );
}

// ---------- query results ----------

function QueryResults({
  definition,
  onFilter,
}: {
  definition: QueryDefinition;
  onFilter: (filter: HuntFilter) => void;
}) {
  const key = JSON.stringify(definition);
  // Cursors belong to the hunt they were issued for (see EventsPage).
  const [paging, setPaging] = useState({ key, cursors: [null] as (string | null)[] });
  const cursors = paging.key === key ? paging.cursors : [null];
  const cursor = cursors[cursors.length - 1];
  const load = useCallback(
    (signal: AbortSignal) => runHunt({ ...definition.query, limit: PAGE_SIZE }, cursor, signal),
    [key, cursor], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const { data, error, loading } = useApi(load);

  if (error) return <HuntError error={error} />;
  if (!data) return <p className="text-sm text-slate-400">Hunting…</p>;
  const around = { from: data.from, to: data.to };
  return (
    <div>
      <p className="mb-2 text-sm text-slate-300" aria-live="polite">
        <span className="font-mono">{data.total_capped ? "10,000+" : data.total.toLocaleString("en-US")}</span>{" "}
        matching {data.total === 1 && !data.total_capped ? "event" : "events"} · {formatUtc(data.from)} –{" "}
        {formatUtc(data.to)}
      </p>
      {data.items.length === 0 ? (
        <p className="text-sm text-slate-400">No events match. Widen the time range or remove a filter.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-3 font-medium">Time</th>
                <th className="py-2 pr-3 font-medium">Event</th>
                <th className="py-2 pr-3 font-medium">Host</th>
                <th className="py-2 pr-3 font-medium">User</th>
                <th className="py-2 pr-3 font-medium">Source</th>
                <th className="py-2 font-medium">Process / destination</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id} className="border-t border-slate-800 align-top">
                  <td className="whitespace-nowrap py-1.5 pr-3 font-mono text-xs text-slate-400">
                    <Link to={`/events/${e.id}`} className="hover:text-sky-300">
                      {formatUtc(e.timestamp)}
                    </Link>
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-slate-100">
                    {e.event_category}/{e.event_action}{" "}
                    <span className={e.event_outcome === "failure" ? "text-amber-300" : ""}>{e.event_outcome}</span>
                    {e.simulated && (
                      <span className="ml-2">
                        <SimulatedTag />
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 pr-3">
                    <PivotValue field="host" value={e.host} onFilter={onFilter} around={around} />
                  </td>
                  <td className="py-1.5 pr-3">
                    <PivotValue field="username" value={e.username} onFilter={onFilter} around={around} />
                  </td>
                  <td className="py-1.5 pr-3">
                    <PivotValue field="source_ip" value={e.source_ip} onFilter={onFilter} around={around} />
                  </td>
                  <td className="py-1.5">
                    {e.process_name ? (
                      <PivotValue field="process_name" value={e.process_name} onFilter={onFilter} around={around} />
                    ) : (
                      <PivotValue field="destination_ip" value={e.destination_ip} onFilter={onFilter} around={around} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <nav aria-label="Pagination" className="mt-3 flex items-center justify-between text-sm">
        <span className="text-slate-400">Page {cursors.length}</span>
        <span className="flex gap-2">
          <Button
            variant="secondary"
            disabled={cursors.length === 1}
            onClick={() => setPaging({ key, cursors: cursors.slice(0, -1) })}
          >
            Previous
          </Button>
          <Button
            variant="secondary"
            disabled={!data.next_cursor}
            onClick={() => setPaging({ key, cursors: [...cursors, data.next_cursor] })}
          >
            Next
          </Button>
        </span>
      </nav>
    </div>
  );
}

// ---------- template results ----------

function Cell({ column, value, around }: { column: TemplateColumn; value: unknown; around: { from: string; to: string } }) {
  if (value === null || value === undefined) return <span className="text-slate-500">—</span>;
  const pivotField: Record<string, string> = { ip: "source_ip", user: "username", host: "host", process: "process_name" };
  if (column.kind in pivotField) return <PivotValue field={pivotField[column.kind]} value={String(value)} around={around} />;
  if (column.kind === "time") return <span className="whitespace-nowrap font-mono text-xs">{formatUtc(String(value))}</span>;
  if (column.kind === "event")
    return (
      <Link to={`/events/${String(value)}`} className="text-xs text-sky-300">
        Open event
      </Link>
    );
  if (column.kind === "list" && Array.isArray(value)) return <span className="font-mono text-xs">{value.join(", ")}</span>;
  return <span className="font-mono text-xs">{String(value)}</span>;
}

function TemplateResults({ definition }: { definition: TemplateDefinition }) {
  const key = JSON.stringify(definition);
  const load = useCallback(
    (signal: AbortSignal) => runTemplate(definition.template_id, definition.params, definition.time_range, signal),
    [key], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const { data, error } = useApi(load);
  if (error) return <HuntError error={error} />;
  if (!data) return <p className="text-sm text-slate-400">Hunting…</p>;
  const around = { from: data.from, to: data.to };
  return (
    <div>
      <p className="mb-2 text-sm text-slate-300" aria-live="polite">
        <span className="font-mono">{data.rows.length}</span> {data.rows.length === 1 ? "result" : "results"}
        {data.truncated && " (the first 200)"} ·{" "}
        {formatUtc(data.from)} – {formatUtc(data.to)}
      </p>
      {data.rows.length === 0 ? (
        <p className="text-sm text-slate-400">Nothing found in this period with these parameters.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                {data.columns.map((c) => (
                  <th key={c.key} className="py-2 pr-3 font-medium">
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.rows.map((row, i) => (
                <tr key={i} className="border-t border-slate-800 align-top">
                  {data.columns.map((c) => (
                    <td key={c.key} className="py-1.5 pr-3 text-slate-200">
                      <Cell column={c} value={row[c.key]} around={around} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------- editors ----------

function QueryEditor({
  fields,
  initial,
  onRun,
}: {
  fields: HuntFields;
  initial: QueryDefinition;
  onRun: (definition: QueryDefinition) => void;
}) {
  const [timeRange, setTimeRange] = useState(initial.query.time_range);
  const [rows, setRows] = useState<FilterRow[]>(initial.query.filters.map(rowFromFilter));
  const [alert, setAlert] = useState<AlertContext>(initial.query.alert ?? {});
  const [ruleText, setRuleText] = useState((initial.query.alert?.rule_ids ?? []).join(", "));
  const [sort, setSort] = useState(initial.query.sort ?? "newest");

  function submit(e: FormEvent) {
    e.preventDefault();
    const rule_ids = ruleText
      .split(",")
      .map((r) => r.trim().toUpperCase())
      .filter(Boolean);
    const context: AlertContext = { ...alert, rule_ids };
    const hasAlert = hasAlertFilters(context);
    onRun({
      kind: "query",
      query: {
        time_range: timeRange,
        filters: rows.map((r) => filterFromRow(r, fields.fields)),
        ...(hasAlert ? { alert: context } : {}),
        ...(sort === "oldest" ? { sort } : {}),
      },
    });
  }

  function toggle<T>(list: T[] | undefined, value: T): T[] {
    const current = list ?? [];
    return current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  }

  return (
    <form onSubmit={submit} aria-label="Hunt query" className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <TimeRangeEditor value={timeRange} onChange={setTimeRange} />
        <Field label="Order">
          <select value={sort} onChange={(e) => setSort(e.target.value as "newest" | "oldest")} className={selectClass}>
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </Field>
      </div>
      <fieldset className="space-y-2">
        <legend className="mb-1 text-sm text-slate-300">Events where all of these are true</legend>
        {rows.length === 0 && <p className="text-xs text-slate-500">No filters: every event in the time range.</p>}
        {rows.map((row, i) => (
          <FilterRowEditor
            key={i}
            row={row}
            index={i}
            fields={fields.fields}
            attributeOps={fields.attribute_operators}
            onChange={(next) => setRows(rows.map((r, j) => (j === i ? next : r)))}
            onRemove={() => setRows(rows.filter((_, j) => j !== i))}
          />
        ))}
        <Button
          variant="secondary"
          disabled={rows.length >= fields.max_filters}
          onClick={() => setRows([...rows, { field: "source_ip", attribute: "", op: "eq", text: "" }])}
        >
          Add filter
        </Button>
      </fieldset>
      <details className="rounded border border-slate-800 p-3" open={hasAlertFilters(initial.query.alert)}>
        <summary className="cursor-pointer text-sm text-slate-300">Alert filters (severity, detection, status)</summary>
        <div className="mt-2 flex flex-wrap items-start gap-4 text-sm">
          <Field label="Evidence in an alert">
            <select
              value={alert.in_alert == null ? "" : String(alert.in_alert)}
              onChange={(e) => setAlert({ ...alert, in_alert: e.target.value === "" ? null : e.target.value === "true" })}
              className={selectClass}
            >
              <option value="">Any event</option>
              <option value="true">Only events in an alert</option>
              <option value="false">Only events in no alert</option>
            </select>
          </Field>
          <Field label="Detection rules" hint="Rule IDs, comma-separated, e.g. AUTH-002">
            <input value={ruleText} onChange={(e) => setRuleText(e.target.value)} className={`${inputClass} w-48`} maxLength={500} />
          </Field>
          <fieldset>
            <legend className="mb-1 text-slate-300">Alert severity</legend>
            {SEVERITIES.map((s) => (
              <label key={s} className="mr-3 inline-flex items-center gap-1 text-slate-300">
                <input type="checkbox" checked={(alert.severities ?? []).includes(s)} onChange={() => setAlert({ ...alert, severities: toggle(alert.severities, s) })} />
                {s}
              </label>
            ))}
          </fieldset>
          <fieldset>
            <legend className="mb-1 text-slate-300">Alert status</legend>
            {STATUSES.map((s) => (
              <label key={s} className="mr-3 inline-flex items-center gap-1 text-slate-300">
                <input type="checkbox" checked={(alert.statuses ?? []).includes(s)} onChange={() => setAlert({ ...alert, statuses: toggle(alert.statuses, s) })} />
                {s.replace("_", " ").toLowerCase()}
              </label>
            ))}
          </fieldset>
        </div>
      </details>
      <Button type="submit">Run hunt</Button>
    </form>
  );
}

function TemplateEditor({
  templates,
  initial,
  onRun,
}: {
  templates: TemplateInfo[];
  initial: TemplateDefinition | null;
  onRun: (definition: TemplateDefinition) => void;
}) {
  const [templateId, setTemplateId] = useState(initial?.template_id ?? templates[0]?.id ?? "");
  const template = templates.find((t) => t.id === templateId);
  const defaults = (t?: TemplateInfo) => Object.fromEntries((t?.params ?? []).map((p) => [p.name, String(p.default)]));
  const [params, setParams] = useState<Record<string, string>>(() =>
    initial ? Object.fromEntries(Object.entries(initial.params).map(([k, v]) => [k, String(v)])) : defaults(template),
  );
  const [timeRange, setTimeRange] = useState(initial?.time_range ?? { last: "7d" });
  if (!template) return <p className="text-sm text-slate-400">No templates available.</p>;

  return (
    <form
      aria-label="Hunt template"
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        onRun({
          kind: "template",
          template_id: template.id,
          params: Object.fromEntries(template.params.map((p) => [p.name, Number(params[p.name] ?? p.default)])),
          time_range: timeRange,
        });
      }}
    >
      <div className="grid gap-2 sm:grid-cols-2">
        {templates.map((t) => (
          <label
            key={t.id}
            className={`block cursor-pointer rounded border p-3 text-sm ${t.id === templateId ? "border-sky-600 bg-slate-800/60" : "border-slate-800 hover:border-slate-600"}`}
          >
            <input
              type="radio"
              name="template"
              className="sr-only"
              checked={t.id === templateId}
              onChange={() => {
                setTemplateId(t.id);
                setParams(defaults(t));
              }}
            />
            <span className="block font-medium text-slate-100">{t.name}</span>
            <span className="block text-xs text-slate-400">{t.question}</span>
            <span className="mt-1 block text-xs text-slate-500">
              ATT&CK {t.technique}
              {t.mirrors_rule && ` · mirrors rule ${t.mirrors_rule}`}
            </span>
          </label>
        ))}
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <TimeRangeEditor value={timeRange} onChange={setTimeRange} />
        {template.params.map((p) => (
          <Field key={p.name} label={p.description} hint={`${p.minimum}–${p.maximum}`}>
            <input
              type="number"
              min={p.minimum}
              max={p.maximum}
              value={params[p.name] ?? ""}
              onChange={(e) => setParams({ ...params, [p.name]: e.target.value })}
              className={`${inputClass} w-28`}
            />
          </Field>
        ))}
      </div>
      <Button type="submit">Run template</Button>
    </form>
  );
}

// ---------- saved hunts ----------

function SavedHunts({ current }: { current: HuntDefinition | null }) {
  const user = useCurrentUser();
  const navigate = useNavigate();
  const [attempt, setAttempt] = useState(0);
  const load = useCallback(
    (signal: AbortSignal) => listSavedHunts(signal),
    [attempt], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const { data, error } = useApi(load);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [shared, setShared] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const canSave = hasRole(user, "ANALYST");

  async function act(action: () => Promise<unknown>) {
    setProblem(null);
    try {
      await action();
      setAttempt((n) => n + 1);
    } catch (err) {
      setProblem(err instanceof ApiError ? err.message : "Could not save.");
    }
  }

  return (
    <Panel title="Saved hunts">
      {error ? (
        <ErrorMessage>{error.message}</ErrorMessage>
      ) : !data ? (
        <p className="text-sm text-slate-400">Loading…</p>
      ) : data.length === 0 ? (
        <p className="text-sm text-slate-400">No saved hunts yet.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {data.map((h: SavedHunt) => (
            <li key={h.id} className="border-t border-slate-800 pt-2 first:border-0 first:pt-0">
              <div className="flex flex-wrap items-center gap-2">
                {h.valid ? (
                  <Link to={huntUrl(h.definition)} className="font-medium text-sky-300 hover:underline">
                    {h.name}
                  </Link>
                ) : (
                  <span className="font-medium text-slate-400">{h.name}</span>
                )}
                {h.shared && <span className="rounded bg-slate-800 px-1.5 text-xs text-slate-300">shared</span>}
                <span className="text-xs text-slate-500">{h.kind === "template" ? "template" : "query"}</span>
              </div>
              {h.description && <p className="text-xs text-slate-400">{h.description}</p>}
              {!h.valid && <p className="text-xs text-amber-300">{h.problem}</p>}
              {!h.is_owner && <p className="text-xs text-slate-500">by {h.owner_email}</p>}
              {h.is_owner && (
                <div className="mt-1 flex gap-3 text-xs">
                  <button type="button" className="text-sky-300 hover:underline" onClick={() => void act(() => updateSavedHunt(h.id, { shared: !h.shared }))}>
                    {h.shared ? "Stop sharing" : "Share with everyone"}
                  </button>
                  <button
                    type="button"
                    className="text-rose-300 hover:underline"
                    onClick={() => {
                      if (window.confirm(`Delete the saved hunt "${h.name}"?`)) void act(() => deleteSavedHunt(h.id));
                    }}
                  >
                    Delete
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {canSave && current && (
        <form
          aria-label="Save this hunt"
          className="mt-4 space-y-2 border-t border-slate-800 pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              const saved = await saveHunt({ name: name.trim(), description: description.trim() || null, definition: current, shared });
              setName("");
              setDescription("");
              navigate(huntUrl(saved.definition));
            });
          }}
        >
          <p className="text-xs text-slate-400">Save the hunt shown ({describeRange(current)}).</p>
          <Field label="Name">
            <input value={name} onChange={(e) => setName(e.target.value)} className={inputClass} maxLength={100} required />
          </Field>
          <Field label="Description">
            <input value={description} onChange={(e) => setDescription(e.target.value)} className={inputClass} maxLength={500} />
          </Field>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} />
            Share with everyone (read-only for others)
          </label>
          <Button type="submit" disabled={!name.trim()}>
            Save hunt
          </Button>
        </form>
      )}
      {problem && (
        <div className="mt-2">
          <ErrorMessage>{problem}</ErrorMessage>
        </div>
      )}
    </Panel>
  );
}

// ---------- page ----------

export function HuntPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q");
  const applied = parseHunt(q);
  const definition = applied ?? NEW_HUNT;
  const [mode, setMode] = useState<"query" | "template">(definition.kind);
  // A pivot link or a saved hunt changes the URL: show its mode.
  useEffect(() => setMode(definition.kind), [q]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadFields = useCallback((signal: AbortSignal) => getHuntFields(signal), []);
  const loadTemplates = useCallback((signal: AbortSignal) => listTemplates(signal), []);
  const fields = useApi(loadFields);
  const templates = useApi(loadTemplates);

  function run(next: HuntDefinition) {
    setParams({ q: JSON.stringify(next) });
  }

  function addFilter(filter: HuntFilter) {
    if (definition.kind !== "query") return;
    run({ ...definition, query: { ...definition.query, filters: [...definition.query.filters, filter] } });
  }

  return (
    <section className="space-y-4">
      <PageHeader
        title="Threat hunting"
        description="Ask new questions of the stored events. Every hunt runs on the real event store, within a time range of at most 31 days; the whole hunt is in the page address, so it can be bookmarked or shared. Click a value in the results to pivot on it."
      />
      <div role="tablist" aria-label="Hunt type" className="flex gap-1">
        {(["query", "template"] as const).map((m) => (
          <button
            key={m}
            role="tab"
            type="button"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className={`rounded px-3 py-1.5 text-sm ${mode === m ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"}`}
          >
            {m === "query" ? "Query builder" : "Templates"}
          </button>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-[1fr_18rem]">
        <div className="min-w-0 space-y-4">
          <Panel title={mode === "query" ? "Query" : "Template"}>
            {mode === "query" ? (
              fields.error ? (
                <ErrorMessage>{fields.error.message}</ErrorMessage>
              ) : !fields.data ? (
                <p className="text-sm text-slate-400">Loading fields…</p>
              ) : (
                <QueryEditor key={q ?? "new"} fields={fields.data} initial={definition.kind === "query" ? definition : NEW_HUNT} onRun={run} />
              )
            ) : templates.error ? (
              <ErrorMessage>{templates.error.message}</ErrorMessage>
            ) : !templates.data ? (
              <p className="text-sm text-slate-400">Loading templates…</p>
            ) : (
              <TemplateEditor key={q ?? "new"} templates={templates.data} initial={definition.kind === "template" ? definition : null} onRun={run} />
            )}
          </Panel>
          {applied && (
            <Panel title="Results">
              {applied.kind === "query" ? <QueryResults definition={applied} onFilter={addFilter} /> : <TemplateResults definition={applied} />}
            </Panel>
          )}
        </div>
        <div className="min-w-0">
          <SavedHunts current={applied} />
        </div>
      </div>
    </section>
  );
}
