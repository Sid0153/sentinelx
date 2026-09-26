import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import { LevelBadge, PriorityBadge, SimulatedTag, StatusText } from "../components/alerts";
import {
  INCIDENT_STATUS_LABEL,
  IncidentStatusText,
  StrengthBadge,
  incidentRef,
  shortList,
} from "../components/incidents";
import {
  Button,
  ErrorMessage,
  Field,
  Panel,
  formatUtc,
  inputClass,
  selectClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/http";
import {
  addNote,
  assignIncident,
  changeEvidence,
  getIncident,
  getTimeline,
  listAssignees,
  renameIncident,
  transitionIncident,
  unlinkAlert,
} from "../services/incidents";
import type {
  EvidenceTag,
  IncidentDetail,
  IncidentDisposition,
  IncidentStatus,
  TimelineEntry,
  UserRef,
} from "../types/api";

const TIMELINE_PAGE = 100;
const TAGS: EvidenceTag[] = ["initial_access", "privilege", "persistence", "benign", "needs_review"];

function message(caught: unknown): string {
  return caught instanceof ApiError ? caught.message : "The change could not be saved.";
}

/** Runs an action, shows the server's refusal, and reloads the incident when it worked. */
function useAction(onDone: () => void) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function run(action: () => Promise<unknown>): Promise<boolean> {
    setBusy(true);
    setError(null);
    try {
      await action();
      onDone();
      return true;
    } catch (caught) {
      setError(message(caught));
      return false;
    } finally {
      setBusy(false);
    }
  }
  return { error, busy, run };
}

// ---------- header: title, rename, assignment ----------

function Header({
  incident,
  canAct,
  onChanged,
}: {
  incident: IncidentDetail;
  canAct: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(incident.title);
  const { error, busy, run } = useAction(() => {
    setEditing(false);
    onChanged();
  });
  const closed = incident.status === "CLOSED";
  return (
    <div>
      <Link to="/incidents" className="text-sm text-sky-300">
        ← Incidents
      </Link>
      {editing ? (
        <form
          aria-label="Rename incident"
          className="mt-2 flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => renameIncident(incident.id, title.trim()));
          }}
        >
          <input
            aria-label="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            maxLength={300}
            className={`${inputClass} max-w-xl`}
          />
          <Button type="submit" disabled={busy || title.trim().length < 3}>
            Save
          </Button>
          <Button variant="secondary" onClick={() => setEditing(false)}>
            Cancel
          </Button>
        </form>
      ) : (
        <h1 className="mt-2 text-lg font-semibold text-slate-100">
          <span className="font-mono text-slate-500">{incidentRef(incident.number)}</span> {incident.title}
          {canAct && !closed && (
            <Button variant="secondary" className="ml-2 align-middle" onClick={() => setEditing(true)}>
              Rename
            </Button>
          )}
        </h1>
      )}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <PriorityBadge score={incident.risk_score} band={incident.risk_band} />
        <IncidentStatusText status={incident.status} />
        <LevelBadge level={incident.severity} label="severity" />
        <span className="text-xs text-slate-400">{incident.alert_count} alerts</span>
        {incident.simulated && <SimulatedTag />}
      </div>
    </div>
  );
}

function Assignment({
  incident,
  canAct,
  onChanged,
}: {
  incident: IncidentDetail;
  canAct: boolean;
  onChanged: () => void;
}) {
  const [people, setPeople] = useState<UserRef[]>([]);
  const { error, busy, run } = useAction(onChanged);
  useEffect(() => {
    if (!canAct) return;
    const controller = new AbortController();
    listAssignees(controller.signal)
      .then(setPeople)
      .catch(() => setPeople([]));
    return () => controller.abort();
  }, [canAct]);
  return (
    <Panel title="Assignment">
      {canAct && incident.status !== "CLOSED" ? (
        <Field label="Assigned to">
          <select
            value={incident.assigned_to?.id ?? ""}
            disabled={busy}
            onChange={(e) => void run(() => assignIncident(incident.id, e.target.value || null))}
            className={selectClass}
          >
            <option value="">Nobody</option>
            {people.map((p) => (
              <option key={p.id} value={p.id}>
                {p.email}
              </option>
            ))}
          </select>
        </Field>
      ) : (
        <p className="text-sm text-slate-300">{incident.assigned_to?.email ?? "Nobody"}</p>
      )}
      {error && <ErrorMessage>{error}</ErrorMessage>}
    </Panel>
  );
}

// ---------- workflow ----------

const TRANSITION_LABEL: Record<IncidentStatus, string> = {
  OPEN: "Open",
  TRIAGED: "Triage",
  INVESTIGATING: "Investigate",
  CONTAINED: "Mark contained",
  RESOLVED: "Resolve",
  CLOSED: "Close",
};

function Workflow({ incident, onChanged }: { incident: IncidentDetail; onChanged: () => void }) {
  const [target, setTarget] = useState<IncidentStatus | null>(null);
  const [disposition, setDisposition] = useState<IncidentDisposition>("confirmed_malicious");
  const [text, setText] = useState("");
  const { error, busy, run } = useAction(() => {
    setTarget(null);
    setText("");
    onChanged();
  });
  const reopening = incident.status === "RESOLVED" && target === "INVESTIGATING";
  const resolving = target === "RESOLVED";
  const needsText = resolving || reopening;
  const label = (s: IncidentStatus) =>
    incident.status === "RESOLVED" && s === "INVESTIGATING" ? "Reopen" : TRANSITION_LABEL[s];

  if (incident.allowed_transitions.length === 0) {
    return (
      <Panel title="Workflow">
        <p className="text-sm text-slate-400">Closed incidents are final.</p>
      </Panel>
    );
  }
  return (
    <Panel title="Workflow">
      <div className="flex flex-wrap gap-2">
        {incident.allowed_transitions.map((s) => (
          <Button
            key={s}
            variant={target === s ? "primary" : "secondary"}
            aria-pressed={target === s}
            onClick={() => setTarget(s)}
          >
            {label(s)}
          </Button>
        ))}
      </div>
      {target && (
        <form
          aria-label="Change incident status"
          className="mt-3 space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() =>
              transitionIncident(incident.id, {
                status: target,
                disposition: resolving ? disposition : undefined,
                resolution: resolving ? text.trim() : undefined,
                reason: reopening ? text.trim() : undefined,
              }),
            );
          }}
        >
          {resolving && (
            <Field label="Disposition">
              <select
                value={disposition}
                onChange={(e) => setDisposition(e.target.value as IncidentDisposition)}
                className={selectClass}
              >
                <option value="confirmed_malicious">Confirmed malicious</option>
                <option value="benign_expected">Benign / expected activity</option>
                <option value="false_positive">False positive</option>
              </select>
            </Field>
          )}
          {needsText && (
            <Field
              label={resolving ? "Resolution summary (required)" : "Reason (required)"}
              hint="Recorded in the incident activity and the audit log."
            >
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={3}
                maxLength={resolving ? 4000 : 2000}
                className={inputClass}
              />
            </Field>
          )}
          {error && <ErrorMessage>{error}</ErrorMessage>}
          <div className="flex gap-2">
            <Button type="submit" disabled={busy || (needsText && text.trim().length < 3)}>
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

// ---------- linked alerts ----------

function LinkedAlerts({
  incident,
  canAct,
  onChanged,
}: {
  incident: IncidentDetail;
  canAct: boolean;
  onChanged: () => void;
}) {
  const [unlinking, setUnlinking] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const { error, busy, run } = useAction(() => {
    setUnlinking(null);
    setReason("");
    onChanged();
  });
  return (
    <Panel title={`Linked alerts (${incident.alerts.length})`}>
      <ul className="space-y-3">
        {incident.alerts.map((link) => (
          <li key={link.alert.id} className="text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <PriorityBadge score={link.alert.priority_score} band={link.alert.priority_band} />
              <Link to={`/alerts/${link.alert.id}`} className="text-slate-100 hover:text-sky-300">
                {link.alert.title}
              </Link>
              <StatusText status={link.alert.status} />
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <StrengthBadge strength={link.link_strength} />
              <span>{link.reason}</span>
            </div>
            {canAct && incident.status !== "CLOSED" && (
              <>
                {unlinking === link.alert.id ? (
                  <form
                    aria-label="Unlink alert"
                    className="mt-2 flex flex-wrap gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void run(() => unlinkAlert(incident.id, link.alert.id, reason.trim()));
                    }}
                  >
                    <input
                      aria-label="Why it does not belong"
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      maxLength={400}
                      className={`${inputClass} max-w-sm`}
                    />
                    <Button type="submit" variant="danger" disabled={busy || reason.trim().length < 3}>
                      Unlink
                    </Button>
                    <Button variant="secondary" onClick={() => setUnlinking(null)}>
                      Cancel
                    </Button>
                  </form>
                ) : (
                  <Button variant="secondary" className="mt-1" onClick={() => setUnlinking(link.alert.id)}>
                    Unlink…
                  </Button>
                )}
              </>
            )}
          </li>
        ))}
      </ul>
      {error && <ErrorMessage>{error}</ErrorMessage>}
    </Panel>
  );
}

// ---------- timeline ----------

function activityText(entry: TimelineEntry): string {
  const a = entry.activity;
  if (!a) return "";
  const d = a.details;
  const who = a.actor ?? "Correlation";
  switch (a.kind) {
    case "CREATED":
      return `${who} opened the incident: ${String(d.reason ?? "")}`;
    case "LINK":
      return `${who} linked "${String(d.title ?? "an alert")}" (${String(d.strength ?? "").toLowerCase()})`;
    case "UNLINK":
      return `${who} unlinked "${String(d.title ?? "an alert")}": ${String(d.reason ?? "")}`;
    case "STATUS":
      return `${who}: ${INCIDENT_STATUS_LABEL[d.from as IncidentStatus] ?? d.from} → ${
        INCIDENT_STATUS_LABEL[d.to as IncidentStatus] ?? d.to
      }${d.resolution ? `: ${String(d.resolution)}` : ""}${d.reason ? `: ${String(d.reason)}` : ""}`;
    case "ASSIGN":
      return `${who} assigned it to ${String(d.to ?? "nobody")}`;
    case "NOTE":
      return `${who} added a note`;
    case "EVIDENCE":
      return `${who} ${d.change === "UNPIN" ? "unpinned" : "pinned"} evidence (${String(d.tag ?? "")})`;
    case "RENAME":
      return `${who} renamed it to "${String(d.to ?? "")}"`;
    default:
      return `${who}: ${a.kind}`;
  }
}

function TimelineRow({
  entry,
  canPin,
  onPin,
}: {
  entry: TimelineEntry;
  canPin: boolean;
  onPin: (eventId: string, tag: EvidenceTag) => void;
}) {
  const [open, setOpen] = useState(false);
  const [tag, setTag] = useState<EvidenceTag>("needs_review");
  const [pinning, setPinning] = useState(false);
  const e = entry.event;
  return (
    <li className="border-t border-slate-800 py-1.5 text-sm">
      <div className="flex flex-wrap items-start gap-x-3">
        <span className="shrink-0 font-mono text-xs text-slate-500">{formatUtc(entry.at)}</span>
        {e && (
          <span className="min-w-0 text-slate-200">
            <span className="font-mono text-xs">
              {e.category}/{e.action} {e.outcome}
            </span>{" "}
            <span className="text-xs text-slate-400">
              {[e.host, e.username && `user ${e.username}`, e.source_ip && `from ${e.source_ip}`]
                .filter(Boolean)
                .join(" · ")}
              {e.rules.length > 0 && ` · evidence for ${e.rules.join(", ")}`}
            </span>
          </span>
        )}
        {entry.alert && (
          <span className="text-amber-200">
            Alert {entry.alert.rule_id}: {entry.alert.title}
          </span>
        )}
        {entry.activity && <span className="text-violet-200">{activityText(entry)}</span>}
      </div>
      {e && (
        <div className="mt-1 flex flex-wrap gap-2 pl-0 sm:pl-44">
          <Button variant="secondary" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? "Hide raw" : "Raw"}
          </Button>
          {canPin &&
            (pinning ? (
              <>
                <select
                  aria-label="Evidence tag"
                  value={tag}
                  onChange={(ev) => setTag(ev.target.value as EvidenceTag)}
                  className={selectClass}
                >
                  {TAGS.map((t) => (
                    <option key={t} value={t}>
                      {t.replace("_", " ")}
                    </option>
                  ))}
                </select>
                <Button
                  onClick={() => {
                    onPin(entry.id, tag);
                    setPinning(false);
                  }}
                >
                  Pin
                </Button>
                <Button variant="secondary" onClick={() => setPinning(false)}>
                  Cancel
                </Button>
              </>
            ) : (
              <Button variant="secondary" onClick={() => setPinning(true)}>
                Pin…
              </Button>
            ))}
        </div>
      )}
      {e && open && (
        // Log content is rendered as text, never as HTML.
        <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-xs text-slate-300">
          {e.raw_text}
        </pre>
      )}
    </li>
  );
}

function Timeline({
  incident,
  canPin,
  onChanged,
}: {
  incident: IncidentDetail;
  canPin: boolean;
  onChanged: () => void;
}) {
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pin = useAction(onChanged);

  const loadPage = useCallback(
    async (from: string | null, replace: boolean) => {
      try {
        const page = await getTimeline(incident.id, from, TIMELINE_PAGE);
        setEntries((current) => (replace ? page.items : [...current, ...page.items]));
        setCursor(page.next_cursor);
        setLoaded(true);
      } catch (caught) {
        setError(message(caught));
      }
    },
    [incident.id],
  );
  // Reload from the start whenever the incident changed (new activity is part of it).
  useEffect(() => {
    void loadPage(null, true);
  }, [loadPage, incident.updated_at]);

  return (
    <Panel title="Timeline">
      <p className="mb-2 text-xs text-slate-500">
        Rebuilt from stored data: the evidence events of the linked alerts, the alerts, and every
        action on the incident, oldest first.
      </p>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {!loaded && !error && <p className="text-sm text-slate-400">Loading timeline…</p>}
      <ol>
        {entries.map((entry) => (
          <TimelineRow
            key={`${entry.kind}-${entry.id}`}
            entry={entry}
            canPin={canPin}
            onPin={(eventId, tag) =>
              void pin.run(() => changeEvidence(incident.id, { event_id: eventId, action: "PIN", tag }))
            }
          />
        ))}
      </ol>
      {pin.error && <ErrorMessage>{pin.error}</ErrorMessage>}
      {cursor && (
        <Button variant="secondary" className="mt-2" onClick={() => void loadPage(cursor, false)}>
          Load more
        </Button>
      )}
    </Panel>
  );
}

// ---------- notes and evidence ----------

function Notes({
  incident,
  canAct,
  onChanged,
}: {
  incident: IncidentDetail;
  canAct: boolean;
  onChanged: () => void;
}) {
  const [body, setBody] = useState("");
  const { error, busy, run } = useAction(() => {
    setBody("");
    onChanged();
  });
  return (
    <Panel title="Analyst notes">
      {incident.notes.length === 0 ? (
        <p className="text-sm text-slate-400">No notes yet.</p>
      ) : (
        <ul className="space-y-2">
          {incident.notes.map((note) => (
            <li key={note.id} className="text-sm">
              <p className="whitespace-pre-wrap text-slate-200">{note.body}</p>
              <p className="text-xs text-slate-500">
                {note.author ?? "—"} · {formatUtc(note.created_at)}
              </p>
            </li>
          ))}
        </ul>
      )}
      {canAct && incident.status !== "CLOSED" && (
        <form
          aria-label="Add note"
          className="mt-3 space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => addNote(incident.id, body));
          }}
        >
          <Field label="New note" hint="Notes cannot be edited or deleted; add a new one to correct.">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={3}
              maxLength={10000}
              className={inputClass}
            />
          </Field>
          {error && <ErrorMessage>{error}</ErrorMessage>}
          <Button type="submit" disabled={busy || body.trim().length === 0}>
            Add note
          </Button>
        </form>
      )}
    </Panel>
  );
}

function Evidence({
  incident,
  canAct,
  onChanged,
}: {
  incident: IncidentDetail;
  canAct: boolean;
  onChanged: () => void;
}) {
  const { error, run } = useAction(onChanged);
  return (
    <Panel title="Pinned evidence">
      {incident.evidence.length === 0 ? (
        <p className="text-sm text-slate-400">Nothing pinned. Pin events from the timeline.</p>
      ) : (
        <ul className="space-y-2">
          {incident.evidence.map((pin) => (
            <li key={pin.id} className="text-sm">
              <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
                {pin.tag}
              </span>{" "}
              <span className="text-slate-200">{pin.label}</span>
              {pin.comment && <div className="text-xs text-slate-400">{pin.comment}</div>}
              <div className="text-xs text-slate-500">
                {pin.pinned_by ?? "—"} · {formatUtc(pin.pinned_at)}
                {canAct && incident.status !== "CLOSED" && (
                  <Button
                    variant="secondary"
                    className="ml-2"
                    onClick={() =>
                      void run(() =>
                        changeEvidence(incident.id, {
                          event_id: pin.event_id ?? undefined,
                          alert_id: pin.alert_id ?? undefined,
                          action: "UNPIN",
                          tag: pin.tag,
                        }),
                      )
                    }
                  >
                    Unpin
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {error && <ErrorMessage>{error}</ErrorMessage>}
    </Panel>
  );
}

// ---------- page ----------

export function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const user = useCurrentUser();
  const canAct = hasRole(user, "ANALYST");
  const load = useCallback((signal: AbortSignal) => getIncident(incidentId, signal), [incidentId]);
  const { data: incident, error, reload } = useApi(load);

  if (error) {
    return (
      <section>
        <Link to="/incidents" className="text-sm text-sky-300">
          ← Incidents
        </Link>
        <div className="mt-3">
          <ErrorMessage>
            {error.status === 404 ? "This incident does not exist." : error.message}
          </ErrorMessage>
        </div>
      </section>
    );
  }
  if (!incident) return <p className="text-sm text-slate-400">Loading incident…</p>;

  return (
    <section className="space-y-4">
      <Header incident={incident} canAct={canAct} onChanged={reload} />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Panel title="Summary">
            <p className="text-sm text-slate-200">{incident.summary}</p>
            <p className="mt-2 text-xs text-slate-500">Opened: {incident.created_reason}</p>
            {incident.resolution && (
              <p className="mt-2 text-sm text-emerald-200">
                Resolution ({incident.disposition?.replace("_", " ")}): {incident.resolution}
              </p>
            )}
          </Panel>
          <LinkedAlerts incident={incident} canAct={canAct} onChanged={reload} />
          <Timeline incident={incident} canPin={canAct && incident.status !== "CLOSED"} onChanged={reload} />
          <Notes incident={incident} canAct={canAct} onChanged={reload} />
        </div>
        <div className="min-w-0 space-y-4">
          {canAct ? (
            <Workflow incident={incident} onChanged={reload} />
          ) : (
            <Panel title="Workflow">
              <p className="text-sm text-slate-400">Analysts and admins can change the status.</p>
            </Panel>
          )}
          <Assignment incident={incident} canAct={canAct} onChanged={reload} />
          <Panel title="Risk">
            <table className="w-full text-sm">
              <tbody>
                {incident.risk_breakdown.map((f) => (
                  <tr key={f.factor} className="border-t border-slate-800">
                    <td className="py-1 pr-3 text-slate-400">{f.factor}</td>
                    <td className="py-1 pr-3 text-slate-200">{f.value}</td>
                    <td className="py-1 text-right font-mono text-slate-200">+{f.points}</td>
                  </tr>
                ))}
                <tr className="border-t border-slate-700">
                  <td className="py-1 pr-3 font-medium text-slate-300" colSpan={2}>
                    Total ({incident.risk_band})
                  </td>
                  <td className="py-1 text-right font-mono font-semibold text-slate-100">
                    {incident.risk_score}
                  </td>
                </tr>
              </tbody>
            </table>
            <p className="mt-2 text-xs text-slate-500">
              SentinelX risk, model version {incident.risk_model_version}: project-specific, not an
              industry standard.
            </p>
          </Panel>
          <Panel title="Affected">
            <dl className="space-y-1 text-sm">
              <div>
                <dt className="text-slate-500">Hosts</dt>
                <dd className="text-slate-200">{shortList(incident.hosts, 20) || "—"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Accounts</dt>
                <dd className="text-slate-200">{shortList(incident.usernames, 20) || "—"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Sources</dt>
                <dd className="text-slate-200">{shortList(incident.source_ips, 20) || "—"}</dd>
              </div>
            </dl>
          </Panel>
          <Evidence incident={incident} canAct={canAct} onChanged={reload} />
          <Panel title="MITRE ATT&CK">
            <ul className="space-y-2 text-sm">
              {incident.mitre.map((t) => (
                <li key={t.technique}>
                  <a href={t.url} target="_blank" rel="noreferrer noopener" className="text-sky-300">
                    {t.technique} {t.name}
                  </a>
                  <div className="text-xs text-slate-500">
                    {t.tactics.join(", ")} · from {t.rules.join(", ")}
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="Recommended response">
            <p className="mb-2 text-xs text-slate-500">
              Recommendations only: SentinelX never changes anything on monitored systems.
            </p>
            {incident.response.map((group) => (
              <div key={group.rule_id} className="mb-2">
                <p className="text-xs font-medium text-slate-400">{group.rule_id}</p>
                <ul className="list-disc space-y-1 pl-5 text-sm text-slate-200">
                  {group.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </div>
            ))}
          </Panel>
          {incident.related_incident && (
            <Panel title="Related incident">
              <p className="text-sm text-slate-300">
                The same activity was handled before:{" "}
                <Link to={`/incidents/${incident.related_incident.id}`} className="text-sky-300">
                  {incidentRef(incident.related_incident.number)} {incident.related_incident.title}
                </Link>{" "}
                ({INCIDENT_STATUS_LABEL[incident.related_incident.status]}).
              </p>
            </Panel>
          )}
        </div>
      </div>
    </section>
  );
}
