import { Navigate, Outlet, useLocation } from "react-router-dom";

import type { Role } from "../types/api";
import { hasRole, useAuth } from "./AuthContext";

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
