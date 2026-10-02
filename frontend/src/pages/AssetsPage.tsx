import { useCallback, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import { ASSET_FIELDS, CRITICALITIES, ENVIRONMENTS, InventoryForm } from "../components/context";
import {
  Button,
  ErrorMessage,
  Field,
  PageHeader,
  Pagination,
  Panel,
  formatUtc,
  inputClass,
  selectClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listAssets, saveAsset } from "../services/inventory";

const PAGE_SIZE = 50;

export function AssetsPage() {
  const user = useCurrentUser();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const search = params.get("search") ?? "";
  const criticality = params.get("criticality") ?? "";
  const environment = params.get("environment") ?? "";
  const status = params.get("status") ?? "active";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [draft, setDraft] = useState(search);
  const [creating, setCreating] = useState(false);

  const load = useCallback(
    (signal: AbortSignal) =>
      listAssets(
        {
          search: search || undefined,
          criticality: criticality || undefined,
          environment: environment || undefined,
          status: status === "all" ? undefined : status,
          offset,
          limit: PAGE_SIZE,
        },
        signal,
      ),
    [search, criticality, environment, status, offset],
  );
  const { data, error, loading } = useApi(load);

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("offset");
    setParams(next);
  }

  return (
    <section>
      <PageHeader
        title="Assets"
        description="The host inventory. Events are matched to an asset by hostname when they arrive; its criticality feeds alert priority. Open alerts count those that involve the host."
      />
      {hasRole(user, "ADMIN") &&
        (creating ? (
          <div className="mb-4">
            <Panel title="New asset">
              <InventoryForm
                fields={ASSET_FIELDS}
                initial={null}
                submitLabel="Add asset"
                onCancel={() => setCreating(false)}
                onSave={async (body) => {
                  const asset = await saveAsset(null, body);
                  navigate(`/assets/${asset.id}`);
                }}
              />
            </Panel>
          </div>
        ) : (
          <div className="mb-3">
            <Button onClick={() => setCreating(true)}>New asset</Button>
          </div>
        ))}
      <form
        aria-label="Asset filters"
        className="mb-3 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setFilter("search", draft.trim());
        }}
      >
        <Field label="Search">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="hostname, owner…"
            className={`${inputClass} w-48`}
            maxLength={128}
          />
        </Field>
        <Field label="Criticality">
          <select value={criticality} onChange={(e) => setFilter("criticality", e.target.value)} className={selectClass}>
            <option value="">All</option>
            {CRITICALITIES.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </Field>
        <Field label="Environment">
          <select value={environment} onChange={(e) => setFilter("environment", e.target.value)} className={selectClass}>
            <option value="">All</option>
            {ENVIRONMENTS.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </Field>
        <Field label="Status">
          <select value={status} onChange={(e) => setFilter("status", e.target.value)} className={selectClass}>
            <option value="active">active</option>
            <option value="retired">retired</option>
            <option value="all">all</option>
          </select>
        </Field>
        <Button type="submit">Search</Button>
      </form>

      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 px-4">
        {error ? (
          <div className="py-3">
            <ErrorMessage>{error.message}</ErrorMessage>
          </div>
        ) : !data ? (
          <p className="py-3 text-sm text-slate-400">Loading assets…</p>
        ) : data.items.length === 0 ? (
          <p className="py-3 text-sm text-slate-400">No assets match.</p>
        ) : (
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="py-2 pr-4 font-medium">Hostname</th>
                <th className="py-2 pr-4 font-medium">Criticality</th>
                <th className="py-2 pr-4 font-medium">Type / environment</th>
                <th className="py-2 pr-4 text-right font-medium">Open alerts</th>
                <th className="py-2 font-medium">Last event</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id} className="border-t border-slate-800 align-top">
                  <td className="py-2 pr-4">
                    <Link to={`/assets/${a.id}`} className="font-mono text-slate-100 hover:text-sky-300">
                      {a.hostname}
                    </Link>
                    {a.status === "retired" && <span className="ml-2 text-xs text-slate-400">retired</span>}
                    {a.owner && <div className="text-xs text-slate-400">{a.owner}</div>}
                  </td>
                  <td className="py-2 pr-4 capitalize text-slate-300">{a.criticality}</td>
                  <td className="py-2 pr-4 text-xs text-slate-400">
                    {a.asset_type.replace("_", " ")} · {a.environment}
                  </td>
                  <td className="py-2 pr-4 text-right font-mono text-slate-200">{a.open_alerts}</td>
                  <td className="whitespace-nowrap py-2 font-mono text-xs text-slate-400">
                    {a.last_seen_at ? formatUtc(a.last_seen_at) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {data && (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={(o) => setFilter("offset", o ? String(o) : "")}
        />
      )}
    </section>
  );
}
