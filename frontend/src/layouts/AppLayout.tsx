import { NavLink, Outlet } from "react-router-dom";

import { hasRole, useAuth, useCurrentUser } from "../auth/AuthContext";
import { Button } from "../components/ui";
import type { Role } from "../types/api";

// Only pages that exist are listed, and only for roles that can use them. Each phase adds its
// own entries. Hiding a link is a convenience; the API enforces access (ADR-0007).
const NAV_ITEMS: { to: string; label: string; minimum: Role }[] = [
  { to: "/incidents", label: "Incidents", minimum: "VIEWER" },
  { to: "/alerts", label: "Alerts", minimum: "VIEWER" },
  { to: "/status", label: "Status", minimum: "VIEWER" },
  { to: "/users", label: "Users", minimum: "ADMIN" },
  { to: "/audit", label: "Audit log", minimum: "ADMIN" },
  { to: "/correlation", label: "Correlation", minimum: "ADMIN" },
  { to: "/settings", label: "Account", minimum: "VIEWER" },
];

export function AppLayout() {
  const user = useCurrentUser();
  const { signOut } = useAuth();

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <span className="font-mono text-sm font-semibold tracking-wider text-slate-100">
            SENTINEL<span className="text-sky-400">X</span>
          </span>
          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {NAV_ITEMS.filter((item) => hasRole(user, item.minimum)).map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `rounded px-2.5 py-1 text-sm ${
                    isActive ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="hidden text-slate-400 sm:inline">{user.email}</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300">
              {user.role}
            </span>
            <Button variant="secondary" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
