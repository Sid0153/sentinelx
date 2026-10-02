import { useState, type FormEvent } from "react";

import { useAuth } from "../auth/AuthContext";
import { disableMfa, enableMfa, startMfaSetup, changePassword } from "../services/auth";
import { ApiError } from "../services/http";
import type { MfaSetup, User } from "../types/api";
import { Button, ErrorMessage, Field, inputClass } from "./ui";

function errorText(caught: unknown, fallback: string): string {
  return caught instanceof ApiError ? caught.message : fallback;
}

/** Changing the password ends every session (the server revokes them), so it signs out. */
export function ChangePasswordForm({ forced = false }: { forced?: boolean }) {
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
          : errorText(caught, "Could not change the password."),
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
        {forced ? "Choose a new password" : "Change password"}
      </h2>
      <Field label={forced ? "Temporary password" : "Current password"}>
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
      <p className="text-xs text-slate-400">
        {forced
          ? "Then sign in again with the new password."
          : "Changing it signs you out on every device."}
      </p>
      <Button type="submit" disabled={saving}>
        {saving ? "Changing…" : "Change password"}
      </Button>
    </form>
  );
}

function CodeInput({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  return (
    <Field label={label}>
      <input
        inputMode="numeric"
        autoComplete="one-time-code"
        required
        maxLength={32}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={inputClass}
      />
    </Field>
  );
}

/** Turning on: setup (secret shown) → a code confirms it → recovery codes shown once. */
function EnableMfa() {
  const { reloadUser } = useAuth();
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function begin() {
    setBusy(true);
    setError(null);
    try {
      setSetup(await startMfaSetup());
    } catch (caught) {
      setError(errorText(caught, "Could not start the setup."));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setRecoveryCodes((await enableMfa(code.trim())).recovery_codes);
      setSetup(null);
    } catch (caught) {
      setError(errorText(caught, "Could not turn on two-factor sign-in."));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (recoveryCodes) {
    return (
      <div className="space-y-2">
        <p role="status" className="text-sm text-emerald-300">
          Two-factor sign-in is on.
        </p>
        <p className="text-sm text-slate-300">
          Save these recovery codes somewhere safe. Each one signs you in once if you lose your
          device. They are shown only now.
        </p>
        <ul aria-label="Recovery codes" className="grid grid-cols-2 gap-1 font-mono text-sm text-slate-100">
          {recoveryCodes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <Button variant="secondary" onClick={() => void reloadUser()}>
          I saved them
        </Button>
      </div>
    );
  }

  if (setup) {
    return (
      <form onSubmit={confirm} className="space-y-3">
        <p className="text-sm text-slate-300">
          In your authenticator app, add an account with this key (time-based, 6 digits), then
          enter the code it shows.
        </p>
        <p aria-label="Setup key" className="break-all rounded bg-slate-950 p-2 font-mono text-sm text-slate-100">
          {setup.secret}
        </p>
        <p className="text-xs text-slate-400">
          Or open the setup link on the device with the app:{" "}
          <a className="text-sky-400 underline" href={setup.otpauth_uri}>
            add to authenticator
          </a>
        </p>
        <CodeInput label="Code from the app" value={code} onChange={setCode} />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        <Button type="submit" disabled={busy}>
          {busy ? "Checking…" : "Turn on"}
        </Button>
      </form>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-sm text-slate-300">
        Off. With it on, signing in also needs a code from an authenticator app.
      </p>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <Button onClick={() => void begin()} disabled={busy}>
        Set up two-factor sign-in
      </Button>
    </div>
  );
}

function DisableMfa() {
  const { reloadUser } = useAuth();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await disableMfa(password, code.trim());
      await reloadUser();
    } catch (caught) {
      setError(errorText(caught, "Could not turn off two-factor sign-in."));
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-3">
      <p className="text-sm text-emerald-300">On. Signing in needs a code from your app.</p>
      <p className="text-xs text-slate-400">To turn it off, confirm your password and a current code.</p>
      <Field label="Password">
        <input
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className={inputClass}
        />
      </Field>
      <CodeInput label="Code from the app or a recovery code" value={code} onChange={setCode} />
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <Button type="submit" variant="danger" disabled={busy}>
        Turn off
      </Button>
    </form>
  );
}

export function TwoFactorPanel({ user }: { user: User }) {
  return (
    <section
      aria-labelledby="mfa-heading"
      className="mt-4 max-w-md space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
    >
      <h2 id="mfa-heading" className="text-sm font-semibold text-slate-100">
        Two-factor sign-in
      </h2>
      {user.mfa_enabled ? <DisableMfa /> : <EnableMfa />}
    </section>
  );
}
