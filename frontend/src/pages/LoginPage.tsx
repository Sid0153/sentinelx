import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { Button, ErrorMessage, Field, inputClass } from "../components/ui";
import { authOptions } from "../services/auth";
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

function messageFor(error: unknown, codeStep: boolean): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return codeStep ? "That code is not correct." : "Invalid email or password.";
    if (error.status === 429) return "Too many attempts. Wait a minute and try again.";
    if (error.status === 422) return codeStep ? "Enter the code." : "Enter your email and password.";
    return error.message;
  }
  return "Sign-in failed. Try again.";
}

export function LoginPage() {
  const { state, signIn, signInAsGuest } = useAuth();
  const location = useLocation();
  const { from, reason } = (location.state ?? {}) as LocationState;
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Two-factor accounts: after the password, a code from the app (or a recovery code).
  const [codeStep, setCodeStep] = useState(false);
  const [useRecovery, setUseRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [guestAccess, setGuestAccess] = useState(false);

  useEffect(() => {
    let cancelled = false;
    // Only a public demo offers it; if the question fails, the page simply does not.
    authOptions()
      .then((options) => !cancelled && setGuestAccess(options.guest_access))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.status === "authenticated") {
    // Only same-app paths: a crafted "from" must not send the user to another site.
    const target = from && from.startsWith("/") && !from.startsWith("//") ? from : "/";
    return <Navigate to={target} replace />;
  }

  function startOver() {
    setCodeStep(false);
    setUseRecovery(false);
    setCode("");
    setPassword("");
    setError(null);
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const second = !codeStep ? {} : useRecovery ? { recovery_code: code.trim() } : { otp: code.trim() };
      await signIn(email, password, second);
    } catch (caught) {
      if (caught instanceof ApiError && caught.code === "mfa_required") {
        setCodeStep(true);
      } else {
        setError(messageFor(caught, codeStep));
        if (codeStep) setCode("");
        else setPassword("");
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function onGuest() {
    setSubmitting(true);
    setError(null);
    try {
      await signInAsGuest();
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.status === 429
          ? "Too many attempts. Wait a minute and try again."
          : "Guest access is not available right now.",
      );
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
            {codeStep ? "Two-factor sign-in" : "Sign in"}
          </h1>
          {reason && !error && !codeStep && (
            <p role="status" className="text-sm text-slate-300">
              {NOTICES[reason]}
            </p>
          )}
          {codeStep ? (
            <>
              <Field
                label={useRecovery ? "Recovery code" : "Code from your authenticator app"}
                hint={useRecovery ? "Each recovery code works once." : undefined}
              >
                <input
                  inputMode={useRecovery ? "text" : "numeric"}
                  autoComplete="one-time-code"
                  required
                  autoFocus
                  maxLength={useRecovery ? 32 : 16}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className={inputClass}
                />
              </Field>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                <button
                  type="button"
                  className="text-sky-400 underline"
                  onClick={() => {
                    setUseRecovery(!useRecovery);
                    setCode("");
                    setError(null);
                  }}
                >
                  {useRecovery ? "Use a code from the app" : "Use a recovery code"}
                </button>
                <button type="button" className="text-slate-400 underline" onClick={startOver}>
                  Start over
                </button>
              </div>
            </>
          ) : (
            <>
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
            </>
          )}
          {error && <ErrorMessage>{error}</ErrorMessage>}
          <Button type="submit" disabled={submitting} className="w-full">
            {submitting ? "Signing in…" : codeStep ? "Verify" : "Sign in"}
          </Button>
        </form>
        {guestAccess && !codeStep && (
          <div className="mt-4 space-y-2 rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm">
            <p className="text-slate-300">
              This is a public demo. Every record in it is <strong>simulated</strong>: a fictional
              company, attacked on paper.
            </p>
            <Button type="button" variant="secondary" disabled={submitting} onClick={onGuest} className="w-full">
              Explore as guest (read-only)
            </Button>
          </div>
        )}
        <p className="mt-4 text-center text-xs text-slate-400">
          Accounts are created by an administrator. There is no self-registration.
        </p>
      </div>
    </main>
  );
}
