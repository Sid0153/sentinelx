import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { Button, ErrorMessage, Field, inputClass } from "../components/ui";
import { ApiError } from "../services/http";

interface LocationState {
  from?: string;
  reason?: "expired" | "signed_out" | "password_changed";
}

const NOTICES: Record<NonNullable<LocationState["reason"]>, string> = {
  expired: "Your session ended. Sign in again to continue.",
  signed_out: "You have signed out.",
  password_changed: "Password changed. Sign in with your new password.",
};

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Invalid email or password.";
    if (error.status === 429) return "Too many attempts. Wait a minute and try again.";
    if (error.status === 422) return "Enter your email and password.";
    return error.message;
  }
  return "Sign-in failed. Try again.";
}

export function LoginPage() {
  const { state, signIn } = useAuth();
  const location = useLocation();
  const { from, reason } = (location.state ?? {}) as LocationState;
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (state.status === "authenticated") {
    // Only same-app paths: a crafted "from" must not send the user to another site.
    const target = from && from.startsWith("/") && !from.startsWith("//") ? from : "/";
    return <Navigate to={target} replace />;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await signIn(email, password);
    } catch (caught) {
      setError(messageFor(caught));
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <p className="mb-6 text-center font-mono text-lg font-semibold tracking-wider text-slate-100">
          SENTINEL<span className="text-sky-400">X</span>
        </p>
        <form
          onSubmit={onSubmit}
          aria-labelledby="login-heading"
          className="space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-6"
        >
          <h1 id="login-heading" className="text-base font-semibold text-slate-100">
            Sign in
          </h1>
          {reason && !error && (
            <p role="status" className="text-sm text-slate-300">
              {NOTICES[reason]}
            </p>
          )}
          <Field label="Email">
            <input
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={inputClass}
            />
          </Field>
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
          {error && <ErrorMessage>{error}</ErrorMessage>}
          <Button type="submit" disabled={submitting} className="w-full">
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="mt-4 text-center text-xs text-slate-500">
          Accounts are created by an administrator. There is no self-registration.
        </p>
      </div>
    </main>
  );
}
