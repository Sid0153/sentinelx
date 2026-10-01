import { useCallback, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { SimulatedTag } from "../components/alerts";
import { ErrorMessage, Panel, formatUtc } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { getEvent } from "../services/inventory";

function Row({ label, children }: { label: string; children: ReactNode }) {
  if (children === null || children === undefined || children === "") return null;
  return (
    <div className="flex gap-3 py-0.5 text-sm">
      <dt className="w-36 shrink-0 text-slate-500">{label}</dt>
      <dd className="min-w-0 break-words font-mono text-xs text-slate-200">{children}</dd>
    </div>
  );
}

export function EventDetailPage() {
  const { eventId = "" } = useParams();
  const load = useCallback((signal: AbortSignal) => getEvent(eventId, signal), [eventId]);
  const { data: event, error } = useApi(load);

  if (error) {
    return (
      <section>
        <Link to="/events" className="text-sm text-sky-300">
          ← Events
        </Link>
        <div className="mt-3">
          <ErrorMessage>{error.status === 404 ? "This event does not exist." : error.message}</ErrorMessage>
        </div>
      </section>
    );
  }
  if (!event) return <p className="text-sm text-slate-400">Loading event…</p>;

  const attributes = Object.entries(event.attributes);
  return (
    <section className="space-y-4">
      <div>
        <Link to="/events" className="text-sm text-sky-300">
          ← Events
        </Link>
        <h1 className="mt-2 flex flex-wrap items-center gap-2 text-lg font-semibold text-slate-100">
          <span className="font-mono">
            {event.event_category}/{event.event_action} {event.event_outcome}
          </span>
          {event.simulated && <SimulatedTag />}
        </h1>
        <p className="text-sm text-slate-400">
          {formatUtc(event.timestamp)} · from log source {event.source_name} ({event.source_type})
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Normalized event">
          <dl>
            <Row label="Host">{event.host}</Row>
            <Row label="Host address">{event.host_ip}</Row>
            <Row label="User">{event.username}</Row>
            <Row label="Domain">{event.user_domain}</Row>
            <Row label="Target account">{event.target_username}</Row>
            <Row label="Source">
              {event.source_ip && `${event.source_ip}${event.source_port ? `:${event.source_port}` : ""}`}
            </Row>
            <Row label="Destination">
              {event.destination_ip &&
                `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}`}
            </Row>
            <Row label="Protocol / service">{[event.protocol, event.service].filter(Boolean).join(" / ")}</Row>
            <Row label="Process">{event.process_name}</Row>
            <Row label="Parent process">{event.parent_process_name}</Row>
            <Row label="Command line">{event.command_line}</Row>
            <Row label="Session">{event.session_id}</Row>
            <Row label="Message">{event.message}</Row>
            <Row label="Ingested">{formatUtc(event.ingested_at)}</Row>
          </dl>
          {attributes.length > 0 && (
            <>
              <h3 className="mt-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Attributes</h3>
              <dl>
                {attributes.map(([key, value]) => (
                  <Row key={key} label={key}>
                    {String(value)}
                  </Row>
                ))}
              </dl>
            </>
          )}
        </Panel>
        <div className="min-w-0 space-y-4">
          <Panel title="Enrichment (at ingest)">
            <dl>
              <Row label="Source scope">{event.source_ip_scope}</Row>
              <Row label="Asset">
                {event.asset_id ? (
                  <Link to={`/assets/${event.asset_id}`} className="text-sky-300">
                    {event.host ?? "asset"} ({event.asset_criticality})
                  </Link>
                ) : (
                  "not in the inventory"
                )}
              </Row>
              <Row label="Identity">
                {event.identity_id ? (
                  <Link to={`/identities/${event.identity_id}`} className="text-sky-300">
                    {event.username} {event.identity_privileged ? "(privileged)" : ""}
                  </Link>
                ) : (
                  "not in the inventory"
                )}
              </Row>
            </dl>
          </Panel>
          <Panel title="Alerts citing this event">
            {event.alerts.length === 0 ? (
              <p className="text-sm text-slate-400">No alert uses this event as evidence.</p>
            ) : (
              <ul className="space-y-1 text-sm">
                {event.alerts.map((a) => (
                  <li key={a.id}>
                    <Link to={`/alerts/${a.id}`} className="text-sky-300">
                      {a.title}
                    </Link>{" "}
                    <span className="text-xs text-slate-500">({a.status})</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Raw record">
            <p className="mb-2 text-xs text-slate-500">
              As received ({event.raw.size_bytes} bytes), parse status {event.raw.parse_status}.
              Shown as text; the stored bytes are never changed.
            </p>
            {/* Log content is rendered as text, never as HTML. */}
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-xs text-slate-300">
              {event.raw.text}
            </pre>
            {event.raw.truncated && <p className="text-xs text-slate-500">Shown up to 4,096 characters.</p>}
          </Panel>
        </div>
      </div>
    </section>
  );
}
