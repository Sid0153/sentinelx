import { useCallback, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import {
  LevelBadge,
  PriorityBadge,
  STATUS_LABEL,
  SimulatedTag,
  StatusText,
} from "../components/alerts";
import {
  Button,
  ErrorMessage,
  Field,
  Pagination,
  formatUtc,
  inputClass,
  selectClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { getAlert, listEvidence, transitionAlert } from "../services/alerts";
import { ApiError } from "../services/http";
import type { AlertDetail, AlertStatus, Disposition, EvidenceEvent } from "../types/api";

const EVIDENCE_PAGE = 25;

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-2 text-sm font-semibold text-slate-200">{title}</h2>
      {children}
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 py-0.5 text-sm">
      <dt className="w-32 shrink-0 text-slate-500">{label}</dt>
      <dd className="min-w-0 break-words text-slate-200">{children ?? "—"}</dd>
    </div>
  );
}

// Facts worth showing as "why it fired"; the rest are in the explanation or the entities.
const FACT_LABELS: Record<string, string> = {
  count: "Events in the detection",
  distinct_count: "Distinct values",
  values_sample: "Values seen",
  threshold: "Rule threshold",
  time_window: "Rule window (s)",
  span: "Activity span (s)",
  gap: "Gap (s)",
  value: "New value",
  history_count: "Earlier events",
  indicator_name: "Indicator",
  command_line: "Command line",
};

function Facts({ facts }: { facts: Record<string, unknown> }) {
  const shown = Object.entries(FACT_LABELS).filter(
    ([key]) => facts[key] !== undefined && facts[key] !== null && facts[key] !== "unknown",
  );
  return (
    <dl>
      {shown.map(([key, label]) => (
        <Row key={key} label={label}>
          <span className="font-mono text-xs">{String(facts[key])}</span>
        </Row>
      ))}
    </dl>
  );
}

function Breakdown({ alert }: { alert: AlertDetail }) {
  return (
    <Panel title="Priority">
      <table className="w-full text-sm">
        <tbody>
          {alert.priority_breakdown.map((f) => (
            <tr key={f.factor} className="border-t border-slate-800">
              <td className="py-1 pr-3 text-slate-400">{f.factor}</td>
              <td className="py-1 pr-3 text-slate-200">{f.value}</td>
              <td className="py-1 text-right font-mono text-slate-200">+{f.points}</td>
            </tr>
          ))}
          <tr className="border-t border-slate-700">
            <td className="py-1 pr-3 font-medium text-slate-300" colSpan={2}>
              Total ({alert.priority_band})
            </td>
            <td className="py-1 text-right font-mono font-semibold text-slate-100">
              {alert.priority_score}
            </td>
          </tr>
        </tbody>
      </table>
      <p className="mt-2 text-xs text-slate-500">
        SentinelX priority score, model version {alert.risk_model_version}: a documented,
        project-specific sum, not an industry standard. Asset and identity points use the
        current inventory.
      </p>
    </Panel>
  );
}

interface TimelineItem {
  at: string;
  text: string;
  detail?: string | null;
}

function timeline(alert: AlertDetail): TimelineItem[] {
  const items: TimelineItem[] = [
    { at: alert.first_event_at, text: "First event of the evidence" },
    { at: alert.last_event_at, text: "Latest event of the evidence" },
    ...alert.history.map((h, i) => ({
      at: h.at,
      text:
        i === 0
          ? `Alert created from a detection (${h.event_count} events)`
          : `Extended by a new detection (+${h.new_evidence} events)`,
      detail: h.explanation,
    })),
    ...alert.activity.map((a) => ({
      at: a.at,
      text: `${a.actor ?? "Someone"}: ${STATUS_LABEL[a.from_status as AlertStatus] ?? a.from_status} → ${
        STATUS_LABEL[a.to_status as AlertStatus] ?? a.to_status
      }${a.disposition ? ` (${a.disposition.replace("_", " ")})` : ""}`,
      detail: a.reason,
    })),
  ];
  return items.sort((a, b) => a.at.localeCompare(b.at));
}

function Timeline({ alert }: { alert: AlertDetail }) {
  return (
    <Panel title="Timeline">
      <ol className="space-y-2">
        {timeline(alert).map((item, i) => (
          <li key={i} className="text-sm">
            <span className="font-mono text-xs text-slate-500">{formatUtc(item.at)}</span>
            <div className="text-slate-200">{item.text}</div>
            {item.detail && <div className="text-xs text-slate-400">{item.detail}</div>}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

function EvidenceRow({ event }: { event: EvidenceEvent }) {
  const [open, setOpen] = useState(false);
  const who = [event.username && `user ${event.username}`, event.source_ip && `from ${event.source_ip}`]
    .filter(Boolean)
    .join(" · ");
  return (
    <>
      <tr className="border-t border-slate-800 align-top">
        <td className="whitespace-nowrap py-1.5 pr-3 font-mono text-xs text-slate-400">
          {formatUtc(event.timestamp)}
        </td>
        <td className="py-1.5 pr-3 font-mono text-xs text-slate-200">
          {event.event_category}/{event.event_action} {event.event_outcome}
        </td>
        <td className="py-1.5 pr-3 text-xs text-slate-300">
          {event.host ?? "—"}
          {who && <span className="text-slate-500"> · {who}</span>}
        </td>
        <td className="py-1.5 text-right">
          <Button variant="secondary" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? "Hide raw" : "Raw"}
          </Button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={4} className="pb-2">
            {/* Log content is rendered as text, never as HTML. */}
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-xs text-slate-300">
              {event.raw_text}
            </pre>
            {event.raw_truncated && (
              <p className="text-xs text-slate-500">Shown up to 4,096 characters.</p>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function Evidence({ alert }: { alert: AlertDetail }) {
  const [offset, setOffset] = useState(0);
  const load = useCallback(
    (signal: AbortSignal) => listEvidence(alert.id, offset, EVIDENCE_PAGE, signal),
    [alert.id, offset],
  );
  const { data, error } = useApi(load);
  return (
    <Panel title="Evidence">
      {alert.evidence_truncated && (
        <p className="mb-2 text-xs text-amber-300">
          More events matched than are linked here: the counts are a lower bound. Search the
          events for the same host, user and time span to see all of them.
        </p>
      )}
      {error ? (
        <ErrorMessage>{error.message}</ErrorMessage>
      ) : !data ? (
        <p className="text-sm text-slate-400">Loading evidence…</p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <tbody>
                {data.items.map((event) => (
                  <EvidenceRow key={event.id} event={event} />
                ))}
              </tbody>
            </table>
          </div>
          <Pagination offset={offset} limit={EVIDENCE_PAGE} total={data.total} onChange={setOffset} />
        </>
      )}
    </Panel>
  );
}

const ACTION_LABEL: Record<AlertStatus, string> = {
  NEW: "Mark new",
  TRIAGED: "Triage",
  IN_PROGRESS: "Start work",
  RESOLVED: "Resolve",
  FALSE_POSITIVE: "False positive",
};

function Actions({ alert, onChanged }: { alert: AlertDetail; onChanged: () => void }) {
  const [target, setTarget] = useState<AlertStatus | null>(null);
  const [disposition, setDisposition] = useState<Disposition>("confirmed_malicious");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const closed = alert.status === "RESOLVED" || alert.status === "FALSE_POSITIVE";
  const needsReason = target === "FALSE_POSITIVE" || (closed && target !== null);
  const label = (s: AlertStatus) => (closed && s === "TRIAGED" ? "Reopen" : ACTION_LABEL[s]);

  async function submit() {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      await transitionAlert(alert.id, {
        status: target,
        disposition: target === "RESOLVED" ? disposition : undefined,
        reason: reason.trim() || undefined,
      });
      setTarget(null);
      setReason("");
      onChanged();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The change could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Workflow">
      <div className="flex flex-wrap gap-2">
        {alert.allowed_transitions.map((s) => (
          <Button
            key={s}
            variant={s === "FALSE_POSITIVE" ? "danger" : target === s ? "primary" : "secondary"}
            onClick={() => setTarget(s)}
            aria-pressed={target === s}
          >
            {label(s)}
          </Button>
        ))}
      </div>
      {target && (
        <form
          aria-label="Change status"
          className="mt-3 space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          {target === "RESOLVED" && (
            <Field label="Disposition">
              <select
                value={disposition}
                onChange={(e) => setDisposition(e.target.value as Disposition)}
                className={selectClass}
              >
                <option value="confirmed_malicious">Confirmed malicious</option>
                <option value="benign_expected">Benign / expected activity</option>
              </select>
            </Field>
          )}
          <Field
            label={needsReason ? "Reason (required)" : "Note (optional)"}
            hint="Recorded in the audit log with your name."
          >
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={2}
              maxLength={2000}
              className={inputClass}
            />
          </Field>
          {error && <ErrorMessage>{error}</ErrorMessage>}
          <div className="flex gap-2">
            <Button type="submit" disabled={busy || (needsReason && reason.trim().length < 3)}>
              {label(target)}
            </Button>
            <Button variant="secondary" onClick={() => setTarget(null)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </Panel>
  );
}

export function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const user = useCurrentUser();
  const load = useCallback((signal: AbortSignal) => getAlert(alertId, signal), [alertId]);
  const { data: alert, error, reload } = useApi(load);

  if (error) {
    return (
      <section>
        <Link to="/alerts" className="text-sm text-sky-300">
          ← Alerts
        </Link>
        <div className="mt-3">
          <ErrorMessage>{error.status === 404 ? "This alert does not exist." : error.message}</ErrorMessage>
        </div>
      </section>
    );
  }
  if (!alert) return <p className="text-sm text-slate-400">Loading alert…</p>;

  const entity = (name: string) => alert.entities[name]?.join(", ") || null;
  return (
    <section className="space-y-4">
      <div>
        <Link to="/alerts" className="text-sm text-sky-300">
          ← Alerts
        </Link>
        <h1 className="mt-2 text-lg font-semibold text-slate-100">{alert.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <PriorityBadge score={alert.priority_score} band={alert.priority_band} />
          <StatusText status={alert.status} />
          <LevelBadge level={alert.severity} label="severity" />
          <LevelBadge level={alert.confidence} label="confidence" />
          <span className="font-mono text-xs text-slate-500">
            {alert.rule_id} v{alert.rule_version}
          </span>
          {alert.simulated && <SimulatedTag />}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Panel title="What happened">
            <p className="text-sm text-slate-200">{alert.explanation}</p>
            {alert.detection_count > 1 && (
              <p className="mt-1 text-xs text-slate-500">
                Latest of {alert.detection_count} detections merged into this alert.
              </p>
            )}
          </Panel>
          <Panel title="Why the rule fired">
            <p className="mb-2 text-sm text-slate-300">{alert.description}</p>
            <Facts facts={alert.facts} />
          </Panel>
          <Panel title="Investigate next">
            <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-200">
              {alert.investigation.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </Panel>
          <Panel title="Recommended response">
            <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-200">
              {alert.response.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </Panel>
          <Evidence alert={alert} />
        </div>

        <div className="min-w-0 space-y-4">
          {hasRole(user, "ANALYST") ? (
            <Actions alert={alert} onChanged={reload} />
          ) : (
            <Panel title="Workflow">
              <p className="text-sm text-slate-400">Analysts and admins can change the status.</p>
            </Panel>
          )}
          {alert.status_note && (
            <Panel title="Latest note">
              <p className="text-sm text-slate-200">{alert.status_note}</p>
              <p className="mt-1 text-xs text-slate-500">
                {alert.status_changed_by ?? "—"} · {formatUtc(alert.status_changed_at)}
              </p>
            </Panel>
          )}
          <Breakdown alert={alert} />
          <Panel title="Entities">
            <dl>
              <Row label="Host">{alert.host ?? entity("host")}</Row>
              <Row label="User">{alert.username ?? entity("username")}</Row>
              <Row label="Target account">{alert.target_username ?? entity("target_username")}</Row>
              <Row label="Source">{alert.source_ip ?? entity("source_ip")}</Row>
              <Row label="Destination">{alert.destination_ip ?? entity("destination_ip")}</Row>
              <Row label="Asset">{alert.asset_hostname ?? "not in the inventory"}</Row>
              <Row label="Identity">{alert.identity_username ?? "not in the inventory"}</Row>
            </dl>
          </Panel>
          <Panel title="MITRE ATT&CK">
            <ul className="space-y-2 text-sm">
              {alert.mitre.map((m) => (
                <li key={m.technique}>
                  <a href={m.url} target="_blank" rel="noreferrer noopener" className="text-sky-300">
                    {m.technique} {m.name}
                  </a>
                  <div className="text-xs text-slate-500">{m.tactics.join(", ")}</div>
                  <div className="text-xs text-slate-400">{m.reason}</div>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-slate-500">ATT&CK v{alert.mitre[0]?.attack_version}</p>
          </Panel>
          <Timeline alert={alert} />
          <Panel title="Related alerts">
            {alert.related.length === 0 ? (
              <p className="text-sm text-slate-400">
                No other alerts share this host, user or source within a day.
              </p>
            ) : (
              <ul className="space-y-2 text-sm">
                {alert.related.map((r) => (
                  <li key={r.id}>
                    <Link to={`/alerts/${r.id}`} className="text-sky-300">
                      {r.title}
                    </Link>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <PriorityBadge score={r.priority_score} band={r.priority_band} />
                      <StatusText status={r.status} />
                      shares {r.shared.join(", ")}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {alert.previous_alert_id && (
              <p className="mt-2 text-xs text-slate-400">
                The same activity was seen before:{" "}
                <Link to={`/alerts/${alert.previous_alert_id}`} className="text-sky-300">
                  earlier alert
                </Link>
                .
              </p>
            )}
          </Panel>
          <Panel title="Incident">
            <p className="text-sm text-slate-400">
              {alert.incident_id ? `Part of incident ${alert.incident_id}.` : "Not part of an incident."}
            </p>
          </Panel>
        </div>
      </div>
    </section>
  );
}
