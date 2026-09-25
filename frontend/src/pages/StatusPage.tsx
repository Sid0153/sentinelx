import { StatusIndicator, type Condition } from "../components/StatusIndicator";
import { useApi } from "../hooks/useApi";
import { getHealth, getReadiness } from "../services/system";
import type { HealthResponse, ReadinessResponse } from "../types/api";

interface SystemStatus {
  health: HealthResponse;
  readiness: ReadinessResponse;
}

async function loadStatus(signal: AbortSignal): Promise<SystemStatus> {
  const [health, readiness] = await Promise.all([getHealth(signal), getReadiness(signal)]);
  return { health, readiness };
}

const DATABASE: Record<ReadinessResponse["checks"]["database"], [Condition, string]> = {
  up: ["ok", "Reachable"],
  down: ["down", "Unreachable"],
};

const MIGRATIONS: Record<ReadinessResponse["checks"]["migrations"], [Condition, string]> = {
  current: ["ok", "Up to date"],
  pending: ["degraded", "Migrations pending"],
  unknown: ["unknown", "Unknown"],
};

function Row({ name, condition, label, hint }: {
  name: string;
  condition: Condition;
  label: string;
  hint?: string;
}) {
  return (
    <div className="flex flex-col gap-1 border-t border-slate-800 py-3 sm:flex-row sm:items-center sm:justify-between">
      <dt className="text-sm text-slate-300">{name}</dt>
      <dd className="flex flex-col gap-0.5 sm:items-end">
        <StatusIndicator condition={condition} label={label} />
        {hint && <span className="text-xs text-slate-500">{hint}</span>}
      </dd>
    </div>
  );
}

export function StatusPage() {
  const { data, error, loading, reload } = useApi(loadStatus);
  const ready = data?.readiness.status === "ok";

  return (
    <section aria-labelledby="status-heading" className="mx-auto max-w-2xl">
      <div className="mb-4 flex items-center justify-between gap-4">
        <h1 id="status-heading" className="text-lg font-semibold text-slate-100">
          System status
        </h1>
        <button
          type="button"
          onClick={reload}
          disabled={loading}
          className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
        >
          {loading ? "Checking…" : "Check again"}
        </button>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900 px-4 pb-1 pt-4">
        {error ? (
          <div role="alert" className="pb-3">
            <StatusIndicator condition="down" label="API unreachable" />
            <p className="mt-2 text-sm text-slate-400">{error.message}</p>
            {error.requestId && (
              <p className="mt-1 font-mono text-xs text-slate-500">Request ID: {error.requestId}</p>
            )}
          </div>
        ) : !data ? (
          <p className="pb-3 text-sm text-slate-400">Checking the platform…</p>
        ) : (
          <>
            <div className="pb-3">
              <StatusIndicator
                condition={ready ? "ok" : "degraded"}
                label={ready ? "Operational" : "Not ready"}
              />
            </div>
            <dl>
              <Row name="API" condition="ok" label="Responding" hint={`Version ${data.health.version}`} />
              <Row
                name="Database"
                condition={DATABASE[data.readiness.checks.database][0]}
                label={DATABASE[data.readiness.checks.database][1]}
              />
              <Row
                name="Database schema"
                condition={MIGRATIONS[data.readiness.checks.migrations][0]}
                label={MIGRATIONS[data.readiness.checks.migrations][1]}
              />
            </dl>
          </>
        )}
      </div>
      <p className="mt-3 text-xs text-slate-500">
        Live values from <span className="font-mono">/api/health</span> and{" "}
        <span className="font-mono">/api/ready</span>.
      </p>
    </section>
  );
}
