import { useCallback, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import { LevelBadge } from "../components/alerts";
import {
  Button,
  ErrorMessage,
  Field,
  Panel,
  formatDuration,
  formatRate,
  formatUtc,
  inputClass,
  selectClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/http";
import { getDetectionMetrics, getRule, listRuleVersions, tuneRule } from "../services/inventory";
import { PERIODS } from "./DetectionsPage";
import type { RuleDetail } from "../types/inventory";

const LEVELS = ["critical", "high", "medium", "low"];
const EXCLUSION_FIELDS = ["source_ip", "username", "target_username", "host"] as const;

interface Exclusion {
  field: (typeof EXCLUSION_FIELDS)[number];
  value: string;
  comment?: string | null;
}

function exclusionsOf(rule: RuleDetail): Exclusion[] {
  const list = rule.definition.exclusions;
  return Array.isArray(list) ? (list as Exclusion[]) : [];
}

const sameExclusions = (a: Exclusion[], b: Exclusion[]) =>
  JSON.stringify(a.map((e) => [e.field, e.value, e.comment ?? null])) ===
  JSON.stringify(b.map((e) => [e.field, e.value, e.comment ?? null]));

/** The allowlist of a rule: events matching an entry are ignored by it. */
function ExclusionsEditor({ value, onChange }: { value: Exclusion[]; onChange: (next: Exclusion[]) => void }) {
  const [field, setField] = useState<Exclusion["field"]>("source_ip");
  const [entry, setEntry] = useState("");
  const [comment, setComment] = useState("");
  return (
    <fieldset className="space-y-2">
      <legend className="mb-1 text-sm text-slate-300">Exclusions (events matching one are ignored by this rule)</legend>
      {value.length === 0 ? (
        <p className="text-xs text-slate-500">None.</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {value.map((e, i) => (
            <li key={`${e.field}-${e.value}-${i}`} className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-200">
                {e.field} = {e.value}
              </span>
              {e.comment && <span className="text-xs text-slate-500">({e.comment})</span>}
              <button
                type="button"
                className="text-xs text-rose-300 hover:underline"
                aria-label={`Remove exclusion ${e.field} ${e.value}`}
                onClick={() => onChange(value.filter((_, j) => j !== i))}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <div role="group" aria-label="New exclusion" className="flex flex-wrap items-end gap-2">
        <select aria-label="Exclusion field" value={field} onChange={(e) => setField(e.target.value as Exclusion["field"])} className={selectClass}>
          {EXCLUSION_FIELDS.map((f) => (
            <option key={f}>{f}</option>
          ))}
        </select>
        <input
          aria-label="Exclusion value"
          value={entry}
          placeholder={field === "source_ip" ? "10.20.0.0/16 or one address" : "value"}
          onChange={(e) => setEntry(e.target.value)}
          className={`${inputClass} w-48`}
          maxLength={253}
        />
        <input
          aria-label="Exclusion comment"
          value={comment}
          placeholder="why (optional)"
          onChange={(e) => setComment(e.target.value)}
          className={`${inputClass} w-48`}
          maxLength={200}
        />
        <Button
          variant="secondary"
          disabled={!entry.trim() || value.length >= 100}
          onClick={() => {
            onChange([...value, { field, value: entry.trim(), comment: comment.trim() || null }]);
            setEntry("");
            setComment("");
          }}
        >
          Add exclusion
        </Button>
      </div>
    </fieldset>
  );
}
const CONFIDENCES = ["high", "medium", "low"];

/** ISO 8601 duration as stored ("PT5M", "P1D", "PT300S") -> seconds. */
export function isoSeconds(iso: string): number {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(iso);
  if (!m) return NaN;
  const [, d, h, min, s] = m.map((v) => Number(v ?? 0));
  return d * 86400 + h * 3600 + min * 60 + s;
}

/** Seconds -> the short form the API accepts and people read: "10s", "5m", "2h", "1d". */
export function shortDuration(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };

function parseShort(text: string): number {
  const m = /^(\d{1,6})([smhd])$/.exec(text.trim());
  return m ? Number(m[1]) * UNIT_SECONDS[m[2]] : NaN;
}

function TuneForm({ rule, onSaved, onCancel }: { rule: RuleDetail; onSaved: () => void; onCancel: () => void }) {
  const { tunable, definition } = rule;
  const window = typeof definition.time_window === "string" ? shortDuration(isoSeconds(definition.time_window)) : "";
  const start = {
    enabled: rule.enabled ? "true" : "false",
    severity: rule.severity as string,
    confidence: rule.confidence as string,
    threshold: definition.threshold == null ? "" : String(definition.threshold),
    time_window: window,
  };
  const [values, setValues] = useState(start);
  const [exclusions, setExclusions] = useState<Exclusion[]>(exclusionsOf(rule));
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const set = (key: keyof typeof start) => (value: string) => setValues({ ...values, [key]: value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    const changes: Record<string, unknown> = {};
    if (values.enabled !== start.enabled) changes.enabled = values.enabled === "true";
    if (values.severity !== start.severity) changes.severity = values.severity;
    if (values.confidence !== start.confidence) changes.confidence = values.confidence;
    if (tunable.threshold && values.threshold !== start.threshold) {
      const n = Number(values.threshold);
      if (!Number.isInteger(n) || n < tunable.threshold.min || n > tunable.threshold.max) {
        setError(`Threshold must be a whole number from ${tunable.threshold.min} to ${tunable.threshold.max}.`);
        return;
      }
      changes.threshold = n;
    }
    if (tunable.time_window && values.time_window !== start.time_window) {
      const seconds = parseShort(values.time_window);
      const min = isoSeconds(tunable.time_window.min);
      const max = isoSeconds(tunable.time_window.max);
      if (Number.isNaN(seconds) || seconds < min || seconds > max) {
        setError(`Time window must look like 10m, 2h or 1d, from ${shortDuration(min)} to ${shortDuration(max)}.`);
        return;
      }
      changes.time_window = values.time_window.trim();
    }
    if (tunable.exclusions && !sameExclusions(exclusions, exclusionsOf(rule))) {
      changes.exclusions = exclusions;
    }
    if (Object.keys(changes).length === 0) {
      setError("Nothing changed.");
      return;
    }
    if (reason.trim().length < 5) {
      setError("Give a reason (at least 5 characters); it is kept in the rule history and the audit log.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await tuneRule(rule.rule_id, { ...changes, reason: reason.trim() });
      onSaved();
    } catch (err) {
      if (err instanceof ApiError) {
        // A 422 says which value was refused (e.g. an exclusion that is not a network).
        const why = err.details.map((d) => `${d.loc.filter((p) => p !== "body").join(" → ")}: ${d.msg.replace(/^Value error, /, "")}`);
        setError([err.message, ...why].join(". "));
      } else setError("Could not save.");
      setSaving(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3" aria-label="Tune rule">
      <div className="grid gap-3 sm:grid-cols-2">
        {tunable.enabled && (
          <Field label="State">
            <select value={values.enabled} onChange={(e) => set("enabled")(e.target.value)} className={`${selectClass} w-full`}>
              <option value="true">enabled</option>
              <option value="false">disabled</option>
            </select>
          </Field>
        )}
        {tunable.severity && (
          <Field label="Severity">
            <select value={values.severity} onChange={(e) => set("severity")(e.target.value)} className={`${selectClass} w-full`}>
              {LEVELS.map((l) => (
                <option key={l}>{l}</option>
              ))}
            </select>
          </Field>
        )}
        {tunable.confidence && (
          <Field label="Confidence">
            <select value={values.confidence} onChange={(e) => set("confidence")(e.target.value)} className={`${selectClass} w-full`}>
              {CONFIDENCES.map((l) => (
                <option key={l}>{l}</option>
              ))}
            </select>
          </Field>
        )}
        {tunable.threshold && (
          <Field label="Threshold" hint={`From ${tunable.threshold.min} to ${tunable.threshold.max}.`}>
            <input
              type="number"
              min={tunable.threshold.min}
              max={tunable.threshold.max}
              value={values.threshold}
              onChange={(e) => set("threshold")(e.target.value)}
              className={inputClass}
            />
          </Field>
        )}
        {tunable.time_window && (
          <Field
            label="Time window"
            hint={`Like 10m, 2h or 1d; from ${shortDuration(isoSeconds(tunable.time_window.min))} to ${shortDuration(isoSeconds(tunable.time_window.max))}.`}
          >
            <input value={values.time_window} onChange={(e) => set("time_window")(e.target.value)} className={inputClass} maxLength={8} />
          </Field>
        )}
      </div>
      {tunable.exclusions && <ExclusionsEditor value={exclusions} onChange={setExclusions} />}
      <Field label="Reason for the change" hint="Required. Kept in the rule history and the audit log.">
        <input value={reason} onChange={(e) => setReason(e.target.value)} className={inputClass} maxLength={500} />
      </Field>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <div className="flex gap-2">
        <Button type="submit" disabled={saving}>
          {saving ? "Saving…" : "Save new version"}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

function Versions({ ruleId, attempt }: { ruleId: string; attempt: number }) {
  const load = useCallback(
    (signal: AbortSignal) => listRuleVersions(ruleId, signal),
    [ruleId, attempt], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const { data, error } = useApi(load);
  if (error) return <ErrorMessage>{error.message}</ErrorMessage>;
  if (!data) return <p className="text-sm text-slate-400">Loading history…</p>;
  return (
    <ol className="space-y-2 text-sm">
      {data.map((v) => (
        <li key={v.version} className="border-t border-slate-800 pt-2 first:border-0 first:pt-0">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-mono text-slate-100">v{v.version}</span>
            <span className="text-xs text-slate-400">
              {v.source === "library" ? "from the library" : "admin change"} · {formatUtc(v.created_at)}
            </span>
          </div>
          {v.change_reason && <p className="text-slate-300">{v.change_reason}</p>}
          {Object.keys(v.overrides).length > 0 && (
            <p className="break-all font-mono text-xs text-slate-500">overrides {JSON.stringify(v.overrides)}</p>
          )}
        </li>
      ))}
    </ol>
  );
}

/** How analysts closed this rule's alerts (brief §45): counted, never estimated. */
function RuleOutcomes({ ruleId }: { ruleId: string }) {
  const [days, setDays] = useState(30);
  const load = useCallback((signal: AbortSignal) => getDetectionMetrics(days, signal), [days]);
  const { data, error } = useApi(load);
  const m = data?.items.find((item) => item.rule_id === ruleId);
  const row = (label: string, value: string) => (
    <div className="flex gap-3">
      <dt className="w-40 shrink-0 text-slate-500">{label}</dt>
      <dd className="font-mono text-slate-200">{value}</dd>
    </div>
  );
  return (
    <Panel title="Analyst outcomes">
      <label className="mb-2 flex items-center gap-2 text-sm text-slate-400">
        Alerts created in
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} className={selectClass}>
          {PERIODS.map((d) => (
            <option key={d} value={d}>
              the last {d} days
            </option>
          ))}
        </select>
      </label>
      {error ? (
        <ErrorMessage>{error.message}</ErrorMessage>
      ) : !m ? (
        <p className="text-sm text-slate-400">Loading…</p>
      ) : m.alerts === 0 ? (
        <p className="text-sm text-slate-400">No alerts from this rule in this period.</p>
      ) : (
        <dl className="text-sm">
          {row("Alerts", `${m.alerts} (${m.open} open)`)}
          {row("Confirmed malicious", String(m.confirmed))}
          {row("Benign or expected", String(m.benign))}
          {row("False positives", `${m.false_positives} · ${formatRate(m.false_positive_rate)} of closed`)}
          {row("Median time to triage", formatDuration(m.median_triage_seconds))}
          {row("Median time to close", formatDuration(m.median_resolve_seconds))}
        </dl>
      )}
    </Panel>
  );
}

export function DetectionDetailPage() {
  const { ruleId = "" } = useParams();
  const user = useCurrentUser();
  const [editing, setEditing] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const load = useCallback(
    (signal: AbortSignal) => getRule(ruleId, signal),
    [ruleId, attempt], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const { data: rule, error } = useApi(load);

  if (error) {
    return (
      <section>
        <Link to="/detections" className="text-sm text-sky-300">
          ← Detection rules
        </Link>
        <div className="mt-3">
          <ErrorMessage>{error.status === 404 ? "This rule does not exist." : error.message}</ErrorMessage>
        </div>
      </section>
    );
  }
  if (!rule) return <p className="text-sm text-slate-400">Loading rule…</p>;

  const canTune = hasRole(user, "ADMIN") && rule.in_library;
  return (
    <section className="space-y-4">
      <div>
        <Link to="/detections" className="text-sm text-sky-300">
          ← Detection rules
        </Link>
        <h1 className="mt-2 text-lg font-semibold text-slate-100">
          <span className="font-mono text-slate-400">{rule.rule_id}</span> {rule.name}
        </h1>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-400">
          <LevelBadge level={rule.severity} label="severity" />
          <span>confidence {rule.confidence}</span>
          <span>· v{rule.version}</span>
          <span className={rule.enabled ? "text-emerald-300" : "text-amber-300"}>
            · {rule.enabled ? "enabled" : "disabled"}
          </span>
          {!rule.in_library && <span>· removed from the library</span>}
        </div>
        <p className="mt-2 max-w-3xl text-sm text-slate-300">{rule.description}</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="min-w-0 space-y-4">
          <Panel title="Tuning">
            {editing ? (
              <TuneForm
                rule={rule}
                onCancel={() => setEditing(false)}
                onSaved={() => {
                  setEditing(false);
                  setAttempt((n) => n + 1);
                }}
              />
            ) : (
              <>
                <p className="text-sm text-slate-400">
                  {Object.keys(rule.overrides).length === 0
                    ? "Running as defined in the library."
                    : `Admin overrides: ${Object.keys(rule.overrides).join(", ")}.`}
                </p>
                <p className="mt-2 text-sm text-slate-400">
                  Exclusions:{" "}
                  {exclusionsOf(rule).length === 0
                    ? "none"
                    : exclusionsOf(rule)
                        .map((e) => `${e.field} = ${e.value}${e.comment ? ` (${e.comment})` : ""}`)
                        .join("; ")}
                </p>
                {canTune && (
                  <div className="mt-3">
                    <Button variant="secondary" onClick={() => setEditing(true)}>
                      Tune rule
                    </Button>
                  </div>
                )}
              </>
            )}
          </Panel>
          <Panel title="MITRE ATT&CK">
            <ul className="space-y-2 text-sm">
              {rule.mitre.map((t) => (
                <li key={`${t.technique_id}-${t.indicator ?? ""}`}>
                  <a href={t.url} target="_blank" rel="noreferrer noopener" className="text-sky-300">
                    <span className="font-mono">{t.technique_id}</span> {t.name}
                  </a>
                  <span className="text-xs text-slate-500"> · {t.tactics.join(", ")}</span>
                  <p className="text-xs text-slate-400">{t.reason}</p>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="Statistics">
            <dl className="text-sm">
              <div className="flex gap-3">
                <dt className="w-32 text-slate-500">Matches</dt>
                <dd className="font-mono text-slate-200">{rule.match_count}</dd>
              </div>
              <div className="flex gap-3">
                <dt className="w-32 text-slate-500">Errors</dt>
                <dd className="font-mono text-slate-200">{rule.error_count}</dd>
              </div>
              <div className="flex gap-3">
                <dt className="w-32 text-slate-500">Last run</dt>
                <dd className="font-mono text-xs text-slate-200">{rule.last_run_at ? formatUtc(rule.last_run_at) : "never"}</dd>
              </div>
              <div className="flex gap-3">
                <dt className="w-32 text-slate-500">Last match</dt>
                <dd className="font-mono text-xs text-slate-200">{rule.last_match_at ? formatUtc(rule.last_match_at) : "never"}</dd>
              </div>
            </dl>
            <Link to={`/alerts?rule_id=${encodeURIComponent(rule.rule_id)}`} className="mt-2 inline-block text-sm text-sky-300">
              Alerts from this rule
            </Link>
          </Panel>
          <RuleOutcomes ruleId={rule.rule_id} />
        </div>
        <div className="min-w-0 space-y-4">
          <Panel title="Definition (as it runs)">
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-xs text-slate-300">
              {JSON.stringify(rule.definition, null, 2)}
            </pre>
          </Panel>
          <Panel title="Version history">
            <Versions ruleId={rule.rule_id} attempt={attempt} />
          </Panel>
        </div>
      </div>
    </section>
  );
}
