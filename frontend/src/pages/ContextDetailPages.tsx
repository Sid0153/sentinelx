import { useCallback, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { hasRole, useCurrentUser } from "../auth/AuthContext";
import { ASSET_FIELDS, ActivityPanels, Fact, IDENTITY_FIELDS, InventoryForm } from "../components/context";
import { Button, ErrorMessage, Panel, formatUtc } from "../components/ui";
import { useApi } from "../hooks/useApi";
import {
  getAsset,
  getAssetActivity,
  getIdentity,
  getIdentityActivity,
  saveAsset,
  saveIdentity,
} from "../services/inventory";
import type { ContextActivity } from "../types/inventory";

function Activity({ load }: { load: (signal: AbortSignal) => Promise<ContextActivity> }) {
  const { data, error } = useApi(load);
  if (error) return <ErrorMessage>{error.message}</ErrorMessage>;
  if (!data) return <p className="text-sm text-slate-400">Loading activity…</p>;
  return <ActivityPanels activity={data} />;
}

function Missing({ back, label, status, message }: { back: string; label: string; status: number; message: string }) {
  return (
    <section>
      <Link to={back} className="text-sm text-sky-300">
        ← {label}
      </Link>
      <div className="mt-3">
        <ErrorMessage>{status === 404 ? "This record does not exist." : message}</ErrorMessage>
      </div>
    </section>
  );
}

function Tags({ tags }: { tags: string[] }) {
  if (tags.length === 0) return <>—</>;
  return (
    <span className="flex flex-wrap gap-1">
      {tags.map((t) => (
        <span key={t} className="rounded bg-slate-800 px-1.5 font-mono text-xs text-slate-300">
          {t}
        </span>
      ))}
    </span>
  );
}

export function AssetDetailPage() {
  const { assetId = "" } = useParams();
  const user = useCurrentUser();
  const [editing, setEditing] = useState(false);
  const load = useCallback((signal: AbortSignal) => getAsset(assetId, signal), [assetId]);
  const loadActivity = useCallback((signal: AbortSignal) => getAssetActivity(assetId, signal), [assetId]);
  const { data: asset, error, reload } = useApi(load);

  if (error) return <Missing back="/assets" label="Assets" status={error.status} message={error.message} />;
  if (!asset) return <p className="text-sm text-slate-400">Loading asset…</p>;

  return (
    <section className="space-y-4">
      <div>
        <Link to="/assets" className="text-sm text-sky-300">
          ← Assets
        </Link>
        <h1 className="mt-2 break-all font-mono text-lg font-semibold text-slate-100">{asset.hostname}</h1>
        <p className="text-sm text-slate-400">
          {asset.criticality} criticality · {asset.asset_type.replace("_", " ")} · {asset.environment} · {asset.status}
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="min-w-0 space-y-4">
          <Panel title="Asset">
            {editing ? (
              <InventoryForm
                fields={ASSET_FIELDS}
                initial={{ ...asset }}
                submitLabel="Save changes"
                onCancel={() => setEditing(false)}
                onSave={async (body) => {
                  await saveAsset(asset.id, body);
                  setEditing(false);
                  reload();
                }}
              />
            ) : (
              <>
                <dl>
                  <Fact label="IP addresses">
                    <span className="font-mono text-xs">{asset.ip_addresses.join(", ") || "—"}</span>
                  </Fact>
                  <Fact label="Owner">{asset.owner ?? "—"}</Fact>
                  <Fact label="Description">{asset.description ?? "—"}</Fact>
                  <Fact label="Tags">
                    <Tags tags={asset.tags} />
                  </Fact>
                  <Fact label="Updated">{formatUtc(asset.updated_at)}</Fact>
                </dl>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Link
                    to={`/events?host=${encodeURIComponent(asset.hostname)}&range=7d`}
                    className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
                  >
                    Events from this host
                  </Link>
                  {hasRole(user, "ADMIN") && (
                    <Button variant="secondary" onClick={() => setEditing(true)}>
                      Edit
                    </Button>
                  )}
                </div>
              </>
            )}
          </Panel>
        </div>
        <div className="min-w-0 space-y-4">
          <Activity load={loadActivity} />
        </div>
      </div>
    </section>
  );
}

export function IdentityDetailPage() {
  const { identityId = "" } = useParams();
  const user = useCurrentUser();
  const [editing, setEditing] = useState(false);
  const load = useCallback((signal: AbortSignal) => getIdentity(identityId, signal), [identityId]);
  const loadActivity = useCallback(
    (signal: AbortSignal) => getIdentityActivity(identityId, signal),
    [identityId],
  );
  const { data: identity, error, reload } = useApi(load);

  if (error) return <Missing back="/identities" label="Identities" status={error.status} message={error.message} />;
  if (!identity) return <p className="text-sm text-slate-400">Loading identity…</p>;

  return (
    <section className="space-y-4">
      <div>
        <Link to="/identities" className="text-sm text-sky-300">
          ← Identities
        </Link>
        <h1 className="mt-2 break-all font-mono text-lg font-semibold text-slate-100">{identity.username}</h1>
        <p className="text-sm text-slate-400">
          {identity.privilege_level} account · {identity.status}
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="min-w-0 space-y-4">
          <Panel title="Identity">
            {editing ? (
              <InventoryForm
                fields={IDENTITY_FIELDS}
                initial={{ ...identity }}
                submitLabel="Save changes"
                onCancel={() => setEditing(false)}
                onSave={async (body) => {
                  await saveIdentity(identity.id, body);
                  setEditing(false);
                  reload();
                }}
              />
            ) : (
              <>
                <dl>
                  <Fact label="Display name">{identity.display_name ?? "—"}</Fact>
                  <Fact label="Department">{identity.department ?? "—"}</Fact>
                  <Fact label="Job title">{identity.title ?? "—"}</Fact>
                  <Fact label="Tags">
                    <Tags tags={identity.tags} />
                  </Fact>
                  <Fact label="Updated">{formatUtc(identity.updated_at)}</Fact>
                </dl>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Link
                    to={`/events?username=${encodeURIComponent(identity.username)}&range=7d`}
                    className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
                  >
                    Events by this account
                  </Link>
                  {hasRole(user, "ADMIN") && (
                    <Button variant="secondary" onClick={() => setEditing(true)}>
                      Edit
                    </Button>
                  )}
                </div>
              </>
            )}
          </Panel>
        </div>
        <div className="min-w-0 space-y-4">
          <Activity load={loadActivity} />
        </div>
      </div>
    </section>
  );
}
