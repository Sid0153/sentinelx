import { useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../services/http";
import type { ContextActivity } from "../types/inventory";
import { PriorityBadge, SimulatedTag, StatusText } from "./alerts";
import { IncidentStatusText, incidentRef } from "./incidents";
import { Button, ErrorMessage, Field, Panel, formatUtc, inputClass, selectClass } from "./ui";

export const CRITICALITIES = ["critical", "high", "medium", "low"];
export const ASSET_TYPES = ["server", "workstation", "network_device", "cloud_instance", "container", "other"];
export const ENVIRONMENTS = ["production", "staging", "development", "test"];
export const PRIVILEGE_LEVELS = ["standard", "privileged", "service"];

/** "a, b  c" -> ["a", "b", "c"]; the backend normalizes and validates each value. */
export function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

/** A small key/value line for detail panels. */
export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 py-0.5 text-sm">
      <dt className="w-32 shrink-0 text-slate-500">{label}</dt>
      <dd className="min-w-0 break-words text-slate-200">{children}</dd>
    </div>
  );
}

/** Alerts and incidents that involve an asset or identity, with their counts. */
export function ActivityPanels({ activity }: { activity: ContextActivity }) {
  return (
    <>
      <Panel title="Activity">
        <dl>
          <Fact label="Open alerts">
            {activity.open_alerts} of {activity.total_alerts}
          </Fact>
          <Fact label="Open incidents">
            {activity.open_incidents} of {activity.total_incidents}
          </Fact>
          <Fact label="Last event">{activity.last_seen_at ? formatUtc(activity.last_seen_at) : "none"}</Fact>
        </dl>
      </Panel>
      <Panel title="Recent alerts">
        {activity.recent_alerts.length === 0 ? (
          <p className="text-sm text-slate-400">No alerts involve it.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {activity.recent_alerts.map((a) => (
              <li key={a.id} className="flex min-w-0 items-start gap-2">
                <PriorityBadge score={a.priority_score} band={a.priority_band} />
                <div className="min-w-0">
                  <Link to={`/alerts/${a.id}`} className="block truncate text-slate-100 hover:text-sky-300">
                    {a.title}
                  </Link>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <StatusText status={a.status} />
                    {formatUtc(a.last_event_at)}
                    {a.simulated && <SimulatedTag />}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel title="Incidents">
        {activity.incidents.length === 0 ? (
          <p className="text-sm text-slate-400">No incidents involve it.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {activity.incidents.map((i) => (
              <li key={i.id} className="flex min-w-0 items-start gap-2">
                <PriorityBadge score={i.risk_score} band={i.risk_band} />
                <div className="min-w-0">
                  <Link to={`/incidents/${i.id}`} className="block truncate text-slate-100 hover:text-sky-300">
                    <span className="font-mono text-xs text-slate-500">{incidentRef(i.number)}</span> {i.title}
                  </Link>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <IncidentStatusText status={i.status} />
                    {i.alert_count} alerts
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}

export interface FieldSpec {
  name: string;
  label: string;
  kind: "text" | "list" | "select";
  options?: string[];
  required?: boolean;
  /** Only when creating (e.g. hostname, which is the asset's identity). */
  createOnly?: boolean;
  /** Only when editing (e.g. status). */
  editOnly?: boolean;
  maxLength?: number;
  hint?: string;
}

type Values = Record<string, string>;

function toText(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  return value === null || value === undefined ? "" : String(value);
}

function toValue(spec: FieldSpec, text: string): unknown {
  if (spec.kind === "list") return splitList(text);
  const trimmed = text.trim();
  return trimmed === "" ? null : trimmed;
}

/**
 * Create or edit form for an inventory record. On edit it sends only the fields that changed
 * (PATCH semantics); an emptied optional text field is sent as null, which clears it.
 */
export function InventoryForm({
  fields,
  initial,
  onSave,
  onCancel,
  submitLabel,
}: {
  fields: FieldSpec[];
  initial: Record<string, unknown> | null;
  onSave: (body: Record<string, unknown>) => Promise<void>;
  onCancel: () => void;
  submitLabel: string;
}) {
  const editing = initial !== null;
  const shown = fields.filter((f) => (editing ? !f.createOnly : !f.editOnly));
  const start: Values = Object.fromEntries(
    shown.map((f) => [f.name, initial ? toText(initial[f.name]) : f.kind === "select" && f.options ? f.options[0] : ""]),
  );
  const [values, setValues] = useState<Values>(start);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const body: Record<string, unknown> = {};
    for (const f of shown) {
      if (editing && values[f.name] === start[f.name]) continue;
      const value = toValue(f, values[f.name]);
      if (!editing && value === null) continue;
      body[f.name] = value;
    }
    if (editing && Object.keys(body).length === 0) {
      setError("Nothing changed.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(body);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save.");
      setSaving(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3" aria-label={submitLabel}>
      <div className="grid gap-3 sm:grid-cols-2">
        {shown.map((f) => (
          <Field key={f.name} label={f.label} hint={f.hint}>
            {f.kind === "select" ? (
              <select
                value={values[f.name]}
                onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
                className={`${selectClass} w-full`}
              >
                {f.options?.map((o) => (
                  <option key={o}>{o}</option>
                ))}
              </select>
            ) : (
              <input
                value={values[f.name]}
                onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
                className={inputClass}
                required={f.required}
                maxLength={f.maxLength}
              />
            )}
          </Field>
        ))}
      </div>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <div className="flex gap-2">
        <Button type="submit" disabled={saving}>
          {saving ? "Saving…" : submitLabel}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export const ASSET_FIELDS: FieldSpec[] = [
  { name: "hostname", label: "Hostname", kind: "text", required: true, createOnly: true, maxLength: 253 },
  { name: "asset_type", label: "Type", kind: "select", options: ASSET_TYPES },
  { name: "environment", label: "Environment", kind: "select", options: ENVIRONMENTS },
  {
    name: "criticality",
    label: "Criticality",
    kind: "select",
    options: CRITICALITIES,
    hint: "Raises the priority of alerts on this host.",
  },
  { name: "ip_addresses", label: "IP addresses", kind: "list", hint: "Separate with commas or spaces." },
  { name: "owner", label: "Owner", kind: "text", maxLength: 128 },
  { name: "description", label: "Description", kind: "text", maxLength: 500 },
  { name: "tags", label: "Tags", kind: "list", hint: "Separate with commas or spaces." },
  {
    name: "status",
    label: "Status",
    kind: "select",
    options: ["active", "retired"],
    editOnly: true,
    hint: "A retired asset is kept, because past events and incidents point to it.",
  },
];

export const IDENTITY_FIELDS: FieldSpec[] = [
  { name: "username", label: "Username", kind: "text", required: true, createOnly: true, maxLength: 256 },
  {
    name: "privilege_level",
    label: "Privilege level",
    kind: "select",
    options: PRIVILEGE_LEVELS,
    hint: "Privileged accounts raise the priority of their alerts.",
  },
  { name: "display_name", label: "Display name", kind: "text", maxLength: 128 },
  { name: "department", label: "Department", kind: "text", maxLength: 128 },
  { name: "title", label: "Job title", kind: "text", maxLength: 128 },
  { name: "tags", label: "Tags", kind: "list", hint: "Separate with commas or spaces." },
  { name: "status", label: "Status", kind: "select", options: ["active", "disabled"], editOnly: true },
];
