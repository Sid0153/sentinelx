import { Navigate, Outlet, useLocation } from "react-router-dom";

import { ChangePasswordForm } from "../components/account";
import { Button } from "../components/ui";
import type { Role } from "../types/api";
import { hasRole, useAuth } from "./AuthContext";

/** After an admin password reset the API refuses everything else until the password is
 * changed (403 password_change_required), so the app shows only this. */
function PasswordChangeRequired() {
  const { signOut } = useAuth();
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md space-y-3">
        <p className="text-sm text-slate-300">
          An administrator reset your password. Choose a new one to continue.
        </p>
        <ChangePasswordForm forced />
        <Button variant="secondary" onClick={() => void signOut()}>
          Sign out
        </Button>
      </div>
    </main>
  );
}

/** Routes that need a signed-in user. The server still checks every API call. */
export function RequireAuth() {
  const { state } = useAuth();
  const location = useLocation();

  if (state.status === "loading") {
    return (
      <p role="status" className="p-6 text-sm text-slate-400">
        Restoring session…
      </p>
    );
  }
  if (state.status === "unauthenticated") {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname + location.search, reason: state.reason }}
      />
    );
  }
  if (state.user.must_change_password) return <PasswordChangeRequired />;
  return <Outlet />;
}

/** Hides pages the role cannot use. A courtesy only: the API enforces the real rule. */
export function RequireRole({ minimum }: { minimum: Role }) {
  const { state } = useAuth();
  if (state.status !== "authenticated" || !hasRole(state.user, minimum)) {
    return (
      <section className="mx-auto max-w-2xl">
        <h1 className="text-lg font-semibold text-slate-100">Not authorized</h1>
        <p className="mt-2 text-sm text-slate-400">
          This page needs the {minimum} role. Ask an administrator if you need access.
        </p>
      </section>
    );
  }
  return <Outlet />;
}
