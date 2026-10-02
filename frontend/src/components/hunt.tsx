import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../services/http";
import { eq, pivotUrl } from "../services/hunt";
import type { FilterValue, HuntFieldInfo, HuntFilter, HuntOperator, TimeRange } from "../types/hunt";
import { ErrorMessage, inputClass, selectClass } from "./ui";

export const OPERATOR_LABEL: Record<HuntOperator, string> = {
  eq: "is",
  ne: "is not",
  in: "is one of",
  not_in: "is none of",
  contains: "contains",
  startswith: "starts with",
  endswith: "ends with",
  cidr: "is in network",
  exists: "is present",
  gt: ">",
  gte: "≥",
  lt: "<",
  lte: "≤",
};

export const RANGE_PRESETS: { value: string; label: string }[] = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "31d", label: "Last 31 days" },
];

// ---------- filter rows ----------

/** One filter row as the form edits it: everything as text until the hunt runs. */
export interface FilterRow {
  field: string; // a field name, or "attributes" with `attribute` as the key
  attribute: string;
  op: HuntOperator;
  text: string;
}

const ATTRIBUTES = "attributes";

export function rowFromFilter(filter: HuntFilter): FilterRow {
  const isAttribute = filter.field.startsWith("attributes.");
  const value = filter.value;
  return {
    field: isAttribute ? ATTRIBUTES : filter.field,
    attribute: isAttribute ? filter.field.slice("attributes.".length) : "",
    op: filter.op,
    text: Array.isArray(value) ? value.join(", ") : value === null ? "" : String(value),
  };
}

function kindOf(row: FilterRow, fields: HuntFieldInfo[]): HuntFieldInfo["kind"] {
  return fields.find((f) => f.field === row.field)?.kind ?? "text";
}

/** The row as the API expects it; the server validates (and explains) everything. */
export function filterFromRow(row: FilterRow, fields: HuntFieldInfo[]): HuntFilter {
  const field = row.field === ATTRIBUTES ? `attributes.${row.attribute.trim()}` : row.field;
  const kind = kindOf(row, fields);
  const one = (text: string): string | number | boolean => {
    const trimmed = text.trim();
    if (kind === "number" && /^\d+$/.test(trimmed)) return Number(trimmed);
    if (kind === "boolean") return trimmed === "true";
    return trimmed;
  };
  let value: FilterValue;
  if (row.op === "exists") value = row.text !== "false";
  else if (row.op === "in" || row.op === "not_in")
    value = row.text
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean)
      .map((v) => one(v) as string | number);
  else value = one(row.text);
  return { field, op: row.op, value };
}

export function operatorsFor(row: FilterRow, fields: HuntFieldInfo[], attributeOps: HuntOperator[]) {
  if (row.field === ATTRIBUTES) return attributeOps;
  return fields.find((f) => f.field === row.field)?.operators ?? [];
}

export function FilterRowEditor({
  row,
  index,
  fields,
  attributeOps,
  onChange,
  onRemove,
}: {
  row: FilterRow;
  index: number;
  fields: HuntFieldInfo[];
  attributeOps: HuntOperator[];
  onChange: (row: FilterRow) => void;
  onRemove: () => void;
}) {
  const ops = operatorsFor(row, fields, attributeOps);
  const kind = row.field === ATTRIBUTES ? "text" : kindOf(row, fields);
  const label = `Filter ${index + 1}`;
  return (
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-2">
      <select
        aria-label={`${label} field`}
        value={row.field}
        onChange={(e) => {
          const next = { ...row, field: e.target.value };
          const allowed = operatorsFor(next, fields, attributeOps);
          onChange({ ...next, op: allowed.includes(row.op) ? row.op : allowed[0] ?? "eq" });
        }}
        className={selectClass}
      >
        {fields.map((f) => (
          <option key={f.field} value={f.field}>
            {f.field}
          </option>
        ))}
        <option value={ATTRIBUTES}>attributes.…</option>
      </select>
      {row.field === ATTRIBUTES && (
        <input
          aria-label={`${label} attribute key`}
          placeholder="key"
          value={row.attribute}
          onChange={(e) => onChange({ ...row, attribute: e.target.value })}
          className={`${inputClass} w-32`}
          maxLength={64}
        />
      )}
      <select
        aria-label={`${label} operator`}
        value={row.op}
        onChange={(e) => onChange({ ...row, op: e.target.value as HuntOperator })}
        className={selectClass}
      >
        {ops.map((op) => (
          <option key={op} value={op}>
            {OPERATOR_LABEL[op]}
          </option>
        ))}
      </select>
      {row.op === "exists" ? (
        <select
          aria-label={`${label} value`}
          value={row.text === "false" ? "false" : "true"}
          onChange={(e) => onChange({ ...row, text: e.target.value })}
          className={selectClass}
        >
          <option value="true">yes</option>
          <option value="false">no (missing or empty)</option>
        </select>
      ) : kind === "boolean" ? (
        <select
          aria-label={`${label} value`}
          value={row.text === "false" ? "false" : "true"}
          onChange={(e) => onChange({ ...row, text: e.target.value })}
          className={selectClass}
        >
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      ) : (
        <input
          aria-label={`${label} value`}
          value={row.text}
          placeholder={
            row.op === "in" || row.op === "not_in"
              ? "a, b, c"
              : row.op === "cidr"
                ? "10.0.0.0/8"
                : kind === "ip"
                  ? "203.0.113.45"
                  : ""
          }
          onChange={(e) => onChange({ ...row, text: e.target.value })}
          className={`${inputClass} w-56`}
          maxLength={2000}
        />
      )}
      <button
        type="button"
        onClick={onRemove}
        className="rounded px-2 py-1 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        aria-label={`Remove filter ${index + 1}`}
      >
        ✕
      </button>
    </div>
  );
}

// ---------- time range ----------

/** datetime-local value (no zone, read as UTC) <-> ISO. */
const toLocalInput = (iso?: string) => (iso ? iso.slice(0, 16) : "");
const fromLocalInput = (value: string) => (value ? `${value}:00Z` : undefined);

export function TimeRangeEditor({ value, onChange }: { value: TimeRange; onChange: (range: TimeRange) => void }) {
  const custom = !value.last;
  return (
    <div className="flex flex-wrap items-end gap-2">
      <label className="block">
        <span className="mb-1 block text-sm text-slate-300">Time range</span>
        <select
          value={custom ? "custom" : value.last}
          onChange={(e) => {
            if (e.target.value === "custom") {
              const to = new Date();
              const from = new Date(to.getTime() - 24 * 3600 * 1000);
              onChange({ from: from.toISOString(), to: to.toISOString() });
            } else onChange({ last: e.target.value });
          }}
          className={selectClass}
        >
          {RANGE_PRESETS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
          {value.last && !RANGE_PRESETS.some((p) => p.value === value.last) && (
            <option value={value.last}>Last {value.last}</option>
          )}
          <option value="custom">Custom (UTC)</option>
        </select>
      </label>
      {custom && (
        <>
          <label className="block">
            <span className="mb-1 block text-sm text-slate-300">From (UTC)</span>
            <input
              type="datetime-local"
              value={toLocalInput(value.from)}
              onChange={(e) => onChange({ ...value, from: fromLocalInput(e.target.value) })}
              className={inputClass}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-sm text-slate-300">To (UTC)</span>
            <input
              type="datetime-local"
              value={toLocalInput(value.to)}
              onChange={(e) => onChange({ ...value, to: fromLocalInput(e.target.value) })}
              className={inputClass}
            />
          </label>
        </>
      )}
    </div>
  );
}

// ---------- errors ----------

/** The server's explanation, with validation details mapped to the form ("Filter 2: ..."). */
export function HuntError({ error }: { error: unknown }) {
  if (!(error instanceof ApiError)) return <ErrorMessage>Something went wrong.</ErrorMessage>;
  const lines = error.details.map((d) => {
    const loc = d.loc.filter((part) => part !== "body");
    let where = loc.join(" → ");
    if (loc[0] === "filters" && typeof loc[1] === "number") where = `Filter ${loc[1] + 1}`;
    else if (loc[0] === "time_range") where = "Time range";
    else if (loc[0] === "params" && loc[1]) where = String(loc[1]);
    else if (loc[0] === "alert") where = "Alert filters";
    return `${where}: ${d.msg.replace(/^Value error, /, "")}`;
  });
  return (
    <div role="alert" className="text-sm text-rose-300">
      <p>{error.message}</p>
      {lines.length > 0 && (
        <ul className="mt-1 list-disc pl-5">
          {lines.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ---------- pivots ----------

/** A value on screen that opens a small menu of hunts on it (investigation pivoting). */
export function PivotValue({
  field,
  value,
  onFilter,
  around,
  className = "",
}: {
  field: string;
  value: string | null | undefined;
  /** Add the value to the current hunt (include or exclude); absent outside the hunt page. */
  onFilter?: (filter: HuntFilter) => void;
  around?: { from: string; to: string };
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  if (!value) return <span className="text-slate-400">—</span>;
  return (
    <span ref={box} className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={`Pivot on ${field} ${value}`}
        className={`break-all text-left font-mono text-xs text-sky-300 hover:underline ${className}`}
      >
        {value}
      </button>
      {open && (
        <span
          role="menu"
          onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
          className="absolute left-0 top-full z-20 mt-1 flex w-56 flex-col rounded border border-slate-700 bg-slate-950 py-1 text-sm shadow-lg"
        >
          {onFilter && (
            <>
              <button
                type="button"
                role="menuitem"
                className="px-3 py-1 text-left text-slate-200 hover:bg-slate-800"
                onClick={() => {
                  setOpen(false);
                  onFilter(eq(field, value));
                }}
              >
                Only {field} = this
              </button>
              <button
                type="button"
                role="menuitem"
                className="px-3 py-1 text-left text-slate-200 hover:bg-slate-800"
                onClick={() => {
                  setOpen(false);
                  onFilter({ field, op: "ne", value });
                }}
              >
                Exclude this {field}
              </button>
            </>
          )}
          <Link
            role="menuitem"
            to={pivotUrl([eq(field, value)], around)}
            onClick={() => setOpen(false)}
            className="px-3 py-1 text-slate-200 hover:bg-slate-800"
          >
            New hunt on this {field}
          </Link>
        </span>
      )}
    </span>
  );
}

/** A plain "Hunt" link for detail pages (events, alerts, incidents, assets, identities). */
export function HuntLink({
  filters,
  around,
  children = "Hunt",
}: {
  filters: HuntFilter[];
  around?: { from: string; to: string };
  children?: string;
}) {
  return (
    <Link
      to={pivotUrl(filters, around)}
      className="rounded border border-slate-700 px-2 py-0.5 text-xs text-sky-300 hover:bg-slate-800"
      title="Open a threat hunt pre-filtered on this value"
    >
      {children}
    </Link>
  );
}
