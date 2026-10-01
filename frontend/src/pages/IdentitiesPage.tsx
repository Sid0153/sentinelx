import { useCallback, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import { IDENTITY_FIELDS, InventoryForm, PRIVILEGE_LEVELS } from "../components/context";
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
import { listIdentities, saveIdentity } from "../services/inventory";

const PAGE_SIZE = 50;

export function IdentitiesPage() {
  const user = useCurrentUser();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const search = params.get("search") ?? "";
  const privilege = params.get("privilege_level") ?? "";
  const status = params.get("status") ?? "active";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [draft, setDraft] = useState(search);
  const [creating, setCreating] = useState(false);

  const load = useCallback(
    (signal: AbortSignal) =>
      listIdentities(
        {
          search: search || undefined,
          privilege_level: privilege || undefined,
          status: status === "all" ? undefined : status,
          offset,
          limit: PAGE_SIZE,
        },
        signal,
      ),
    [search, privilege, status, offset],
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
        title="Identities"
        description="Known user and service accounts. Events are matched to an identity by username when they arrive; privileged accounts raise alert priority. Open alerts count those where the account is the actor or the target."
      />
      {hasRole(user, "ADMIN") &&
        (creating ? (
          <div className="mb-4">
            <Panel title="New identity">
              <InventoryForm
                fields={IDENTITY_FIELDS}
                initial={null}
                submitLabel="Add identity"
                onCancel={() => setCreating(false)}
                onSave={async (body) => {
                  const identity = await saveIdentity(null, body);
                  navigate(`/identities/${identity.id}`);
                }}
              />
            </Panel>
          </div>
        ) : (
          <div className="mb-3">
            <Button onClick={() => setCreating(true)}>New identity</Button>
          </div>
        ))}
      <form
        aria-label="Identity filters"
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
            placeholder="username, name…"
            className={`${inputClass} w-48`}
            maxLength={128}
          />
        </Field>
        <Field label="Privilege level">
          <select value={privilege} onChange={(e) => setFilter("privilege_level", e.target.value)} className={selectClass}>
            <option value="">All</option>
            {PRIVILEGE_LEVELS.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </Field>
        <Field label="Status">
          <select value={status} onChange={(e) => setFilter("status", e.target.value)} className={selectClass}>
            <option value="active">active</option>
            <option value="disabled">disabled</option>
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
          <p className="py-3 text-sm text-slate-400">Loading identities…</p>
        ) : data.items.length === 0 ? (
          <p className="py-3 text-sm text-slate-400">No identities match.</p>
        ) : (
          <table className={`w-full text-left text-sm ${loading ? "opacity-60" : ""}`}>
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Username</th>
                <th className="py-2 pr-4 font-medium">Privilege</th>
                <th className="py-2 pr-4 font-medium">Department</th>
                <th className="py-2 pr-4 text-right font-medium">Open alerts</th>
                <th className="py-2 font-medium">Last event</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((i) => (
                <tr key={i.id} className="border-t border-slate-800 align-top">
                  <td className="py-2 pr-4">
                    <Link to={`/identities/${i.id}`} className="font-mono text-slate-100 hover:text-sky-300">
                      {i.username}
                    </Link>
                    {i.status === "disabled" && <span className="ml-2 text-xs text-slate-500">disabled</span>}
                    {i.display_name && <div className="text-xs text-slate-500">{i.display_name}</div>}
                  </td>
                  <td className="py-2 pr-4 text-slate-300">{i.privilege_level}</td>
                  <td className="py-2 pr-4 text-xs text-slate-400">{i.department ?? "—"}</td>
                  <td className="py-2 pr-4 text-right font-mono text-slate-200">{i.open_alerts}</td>
                  <td className="whitespace-nowrap py-2 font-mono text-xs text-slate-400">
                    {i.last_seen_at ? formatUtc(i.last_seen_at) : "—"}
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
