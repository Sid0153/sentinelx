import { useCallback, useState, type FormEvent } from "react";

import { useCurrentUser } from "../auth/AuthContext";
import {
  Button,
  ErrorMessage,
  Field,
  formatUtc,
  inputClass,
  PageHeader,
  Pagination,
  selectClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { createUser, listUsers, updateUser } from "../services/admin";
import { ApiError } from "../services/http";
import type { Role, User } from "../types/api";

const ROLES: Role[] = ["VIEWER", "ANALYST", "ADMIN"];
const PAGE_SIZE = 25;

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : "Something went wrong.";
}

function CreateUserForm({ onCreated }: { onCreated: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("VIEWER");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await createUser(email, password, role);
      setEmail("");
      setPassword("");
      setRole("VIEWER");
      onCreated();
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.status === 422
          ? "Check the email address and use a password of 12 to 128 characters."
          : errorText(caught),
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      aria-label="Create user"
      className="grid gap-3 rounded-lg border border-slate-800 bg-slate-900 p-4 sm:grid-cols-[1fr_1fr_auto_auto] sm:items-end"
    >
      <Field label="Email">
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className={inputClass}
        />
      </Field>
      <Field label="Initial password">
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className={inputClass}
        />
      </Field>
      <Field label="Role">
        <select value={role} onChange={(e) => setRole(e.target.value as Role)} className={selectClass}>
          {ROLES.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
      </Field>
      <Button type="submit" disabled={saving}>
        {saving ? "Creating…" : "Create user"}
      </Button>
      {error && (
        <div className="sm:col-span-4">
          <ErrorMessage>{error}</ErrorMessage>
        </div>
      )}
    </form>
  );
}

function UserRow({ user, isSelf, onChanged }: { user: User; isSelf: boolean; onChanged: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function change(changes: { role?: Role; is_active?: boolean }) {
    setBusy(true);
    setError(null);
    try {
      await updateUser(user.id, changes);
      onChanged();
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr className="border-t border-slate-800 align-top">
      <td className="py-2 pr-4 text-slate-100">
        {user.email}
        {isSelf && <span className="ml-2 text-xs text-slate-500">(you)</span>}
        {error && <ErrorMessage>{error}</ErrorMessage>}
      </td>
      <td className="py-2 pr-4">
        <select
          aria-label={`Role of ${user.email}`}
          value={user.role}
          disabled={isSelf || busy}
          onChange={(e) => change({ role: e.target.value as Role })}
          className={selectClass}
        >
          {ROLES.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
      </td>
      <td className="py-2 pr-4">
        <span className={user.is_active ? "text-emerald-300" : "text-slate-500"}>
          {user.is_active ? "Active" : "Deactivated"}
        </span>
      </td>
      <td className="whitespace-nowrap py-2 pr-4 font-mono text-xs text-slate-400">
        {formatUtc(user.last_login_at)}
      </td>
      <td className="py-2 text-right">
        {!isSelf && (
          <Button
            variant={user.is_active ? "danger" : "secondary"}
            disabled={busy}
            onClick={() => change({ is_active: !user.is_active })}
          >
            {user.is_active ? "Deactivate" : "Reactivate"}
          </Button>
        )}
      </td>
    </tr>
  );
}

export function UsersPage() {
  const me = useCurrentUser();
  const [offset, setOffset] = useState(0);
  const load = useCallback(
    (signal: AbortSignal) => listUsers(offset, PAGE_SIZE, signal),
    [offset],
  );
  const { data, error, reload } = useApi(load);

  return (
    <section>
      <PageHeader
        title="Users"
        description="Users are never deleted, only deactivated, so the audit trail keeps pointing at them. Deactivating ends their sessions immediately."
      />
      <CreateUserForm onCreated={reload} />
      <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 px-4">
        {error ? (
          <div className="py-3">
            <ErrorMessage>{error.message}</ErrorMessage>
          </div>
        ) : !data ? (
          <p className="py-3 text-sm text-slate-400">Loading users…</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-4 font-medium">Email</th>
                <th className="py-2 pr-4 font-medium">Role</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Last sign-in</th>
                <th className="py-2 font-medium">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((user) => (
                <UserRow key={user.id} user={user} isSelf={user.id === me.id} onChanged={reload} />
              ))}
            </tbody>
          </table>
        )}
      </div>
      {data && (
        <Pagination offset={offset} limit={PAGE_SIZE} total={data.total} onChange={setOffset} />
      )}
    </section>
  );
}
