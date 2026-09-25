import { NavLink, Outlet } from "react-router-dom";

// Only pages that exist are listed. Each phase adds its own entries.
const NAV_ITEMS = [{ to: "/status", label: "Status" }];

export function AppLayout() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
          <span className="font-mono text-sm font-semibold tracking-wider text-slate-100">
            SENTINEL<span className="text-sky-400">X</span>
          </span>
          <nav aria-label="Main" className="flex gap-1">
            {NAV_ITEMS.map((item) => (
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
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
