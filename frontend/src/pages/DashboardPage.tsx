import { useCallback, useState } from "react";
import { Link } from "react-router-dom";

import { PriorityBadge, SimulatedTag, StatusText } from "../components/alerts";
import { DailyColumns, SERIES_COLOR, SEVERITY_COLOR, SeverityBars } from "../components/charts";
import { IncidentStatusText, incidentRef } from "../components/incidents";
import { ErrorMessage, Panel, formatUtc, selectClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { getDashboard, getTrends } from "../services/inventory";
import type { Level } from "../types/api";

const LEVELS: Level[] = ["critical", "high", "medium", "low"];

function Tile({
  label,
  value,
  detail,
  to,
}: {
  label: string;
  value: number;
  detail?: string;
  to?: string;
}) {
  const body = (
    <>
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 font-mono text-2xl text-slate-100">{value.toLocaleString("en-US")}</div>
      {detail && <div className="mt-0.5 text-xs text-slate-500">{detail}</div>}
    </>
  );
  const style = "block min-w-0 rounded-lg border border-slate-800 bg-slate-900 p-3";
  return to ? (
    <Link to={to} className={`${style} hover:border-slate-600`}>
      {body}
    </Link>
  ) : (
    <div className={style}>{body}</div>
  );
}

function Trends() {
  const [days, setDays] = useState(14);
  const load = useCallback((signal: AbortSignal) => getTrends(days, signal), [days]);
  const { data, error } = useApi(load);
  return (
    <Panel title="Trends">
      <div className="mb-2 flex items-center gap-2 text-sm">
        <label className="text-slate-400" htmlFor="trend-days">
          Period
        </label>
        <select
          id="trend-days"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className={selectClass}
        >
          <option value={7}>7 days</option>
          <option value={14}>14 days</option>
          <option value={30}>30 days</option>
        </select>
        <span className="text-xs text-slate-500">per UTC day</span>
      </div>
      {error ? (
        <ErrorMessage>{error.message}</ErrorMessage>
      ) : !data ? (
        <p className="text-sm text-slate-400">Loading trends…</p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <DailyColumns
            title="Alerts created"
            days={data.items.map((d) => d.day)}
            series={LEVELS.map((l) => ({ key: l, label: l, color: SEVERITY_COLOR[l] }))}
            values={data.items.map((d) => LEVELS.map((l) => d.alerts[l]))}
          />
          <DailyColumns
            title="Incidents opened"
            days={data.items.map((d) => d.day)}
            series={[{ key: "incidents", label: "incidents", color: SERIES_COLOR }]}
            values={data.items.map((d) => [d.incidents])}
          />
          <DailyColumns
            title="Events (by event time)"
            days={data.items.map((d) => d.day)}
            series={[{ key: "events", label: "events", color: SERIES_COLOR }]}
            values={data.items.map((d) => [d.events])}
          />
        </div>
      )}
    </Panel>
  );
}

export function DashboardPage() {
  const load = useCallback((signal: AbortSignal) => getDashboard(signal), []);
  const { data, error } = useApi(load);

  if (error) return <ErrorMessage>{error.message}</ErrorMessage>;
  if (!data) return <p className="text-sm text-slate-400">Loading dashboard…</p>;

  const noData = data.records_processed === 0;
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-lg font-semibold text-slate-100">SOC dashboard</h1>
        <span className="text-xs text-slate-500">
          Counted from the database at {formatUtc(data.generated_at)}
        </span>
      </div>
      {noData && (
        <p className="rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm text-slate-300">
          No data yet. Send logs to a log source (the ingest API or <code>cli ingest-file</code>), or
          load a simulated scenario with <code>cli demo-ingest</code>. Every number below is counted
          from what has been ingested.
        </p>
      )}
      {data.open_alerts_simulated > 0 && (
        <p className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <SimulatedTag /> {data.open_alerts_simulated} of {data.open_alerts} open alerts come
          from simulated demo records.
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Tile label="Records processed" value={data.records_processed} detail="raw records received" />
        <Tile
          label="Events stored"
          value={data.events_stored}
          detail={`${data.events_today.toLocaleString("en-US")} today`}
          to="/events"
        />
        <Tile label="Alerts today" value={data.alerts_today} detail={`${data.open_alerts} open`} to="/alerts" />
        <Tile label="Critical alerts" value={data.critical_alerts} detail="open" to="/alerts?severity=critical" />
        <Tile label="High alerts" value={data.high_alerts} detail="open" to="/alerts?severity=high" />
        <Tile
          label="Open incidents"
          value={data.open_incidents}
          detail={`${data.incidents_under_investigation} under investigation`}
          to="/incidents"
        />
        <Tile
          label="Monitored hosts"
          value={data.monitored_hosts}
          detail={`sent events in 24 h · ${data.inventory_assets} in inventory`}
          to="/assets"
        />
        <Tile
          label="Active rules"
          value={data.active_rules}
          detail={`of ${data.library_rules} in the library`}
          to="/detections"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Open alerts by severity">
          <SeverityBars counts={data.severity_distribution} />
        </Panel>
        <Panel title="Top rules (7 days)">
          {data.top_rules.length === 0 ? (
            <p className="text-sm text-slate-400">No alerts in the last 7 days.</p>
          ) : (
            <ol className="space-y-1 text-sm">
              {data.top_rules.map((r) => (
                <li key={r.rule_id} className="flex justify-between gap-2">
                  <Link to={`/detections/${r.rule_id}`} className="min-w-0 truncate text-sky-300">
                    <span className="font-mono text-xs text-slate-500">{r.rule_id}</span> {r.name}
                  </Link>
                  <span className="font-mono text-slate-200">{r.alerts}</span>
                </li>
              ))}
            </ol>
          )}
        </Panel>
        <Panel title="Top source addresses (7 days)">
          {data.top_source_ips.length === 0 ? (
            <p className="text-sm text-slate-400">No alerts with a source address in the last 7 days.</p>
          ) : (
            <ol className="space-y-1 text-sm">
              {data.top_source_ips.map((s) => (
                <li key={s.source_ip} className="flex justify-between gap-2">
                  <Link
                    to={`/events?source_ip=${encodeURIComponent(s.source_ip)}&range=7d`}
                    className="font-mono text-sky-300"
                  >
                    {s.source_ip}
                  </Link>
                  <span className="font-mono text-slate-200">
                    {s.alerts} alert{s.alerts === 1 ? "" : "s"}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>

      <Trends />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Recent alerts">
          {data.recent_alerts.length === 0 ? (
            <p className="text-sm text-slate-400">No alerts yet.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {data.recent_alerts.map((a) => (
                <li key={a.id} className="flex min-w-0 items-start gap-2">
                  <PriorityBadge score={a.priority_score} band={a.priority_band} />
                  <div className="min-w-0">
                    <Link to={`/alerts/${a.id}`} className="block truncate text-slate-100 hover:text-sky-300">
                      {a.title}
                    </Link>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <StatusText status={a.status} />
                      {formatUtc(a.created_at)}
                      {a.simulated && <SimulatedTag />}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Recent incidents">
          {data.recent_incidents.length === 0 ? (
            <p className="text-sm text-slate-400">No incidents yet.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {data.recent_incidents.map((i) => (
                <li key={i.id} className="flex min-w-0 items-start gap-2">
                  <PriorityBadge score={i.risk_score} band={i.risk_band} />
                  <div className="min-w-0">
                    <Link to={`/incidents/${i.id}`} className="block truncate text-slate-100 hover:text-sky-300">
                      <span className="font-mono text-xs text-slate-500">{incidentRef(i.number)}</span>{" "}
                      {i.title}
                    </Link>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <IncidentStatusText status={i.status} />
                      {i.alert_count} alerts · {formatUtc(i.created_at)}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </section>
  );
}
