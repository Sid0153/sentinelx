import { useState, type FormEvent } from "react";

import { useAuth, useCurrentUser } from "../auth/AuthContext";
import { Button, ErrorMessage, Field, formatUtc, inputClass, PageHeader } from "../components/ui";
import { changePassword } from "../services/auth";
import { ApiError } from "../services/http";

function ChangePasswordForm() {
  const { signOut } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (next !== repeat) {
      setError("The new passwords do not match.");
      return;
    }
    setSaving(true);
    try {
      await changePassword(current, next);
      // The server ended every session, including this one.
      await signOut("password_changed");
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.status === 422
          ? "The new password must be 12 to 128 characters."
          : caught instanceof ApiError
            ? caught.message
            : "Could not change the password.",
      );
      setSaving(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      aria-labelledby="password-heading"
      className="max-w-md space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
    >
      <h2 id="password-heading" className="text-sm font-semibold text-slate-100">
        Change password
      </h2>
      <Field label="Current password">
        <input
          type="password"
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          className={inputClass}
        />
      </Field>
      <Field label="New password" hint="12 to 128 characters. A long passphrase is best.">
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          className={inputClass}
        />
      </Field>
      <Field label="Repeat new password">
        <input
          type="password"
          autoComplete="new-password"
          required
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
          className={inputClass}
        />
      </Field>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <p className="text-xs text-slate-500">Changing it signs you out on every device.</p>
      <Button type="submit" disabled={saving}>
        {saving ? "Changing…" : "Change password"}
      </Button>
    </form>
  );
}

export function SettingsPage() {
  const user = useCurrentUser();
  return (
    <section>
      <PageHeader title="Account" />
      <dl className="mb-4 grid max-w-md grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-400">Email</dt>
        <dd className="text-slate-100">{user.email}</dd>
        <dt className="text-slate-400">Role</dt>
        <dd className="text-slate-100">{user.role}</dd>
        <dt className="text-slate-400">Last sign-in</dt>
        <dd className="font-mono text-xs text-slate-300">{formatUtc(user.last_login_at)}</dd>
      </dl>
      <ChangePasswordForm />
    </section>
  );
}
