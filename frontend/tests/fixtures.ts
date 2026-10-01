import type { Level } from "../src/types/api";
import type { DashboardSummary, TrendDay } from "../src/types/inventory";
import type { Routes } from "./mockApi";

export function dashboardSummary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    generated_at: "2026-09-27T10:00:00Z",
    records_processed: 1240,
    events_stored: 1203,
    events_today: 312,
    alerts_today: 4,
    open_alerts: 9,
    open_alerts_simulated: 0,
    critical_alerts: 2,
    high_alerts: 3,
    severity_distribution: [
      { severity: "critical", count: 2 },
      { severity: "high", count: 3 },
      { severity: "medium", count: 4 },
      { severity: "low", count: 0 },
    ],
    open_incidents: 3,
    incidents_under_investigation: 1,
    monitored_hosts: 7,
    inventory_assets: 12,
    active_rules: 8,
    library_rules: 9,
    top_rules: [{ rule_id: "AUTH-001", name: "Repeated failed logons", alerts: 5 }],
    top_source_ips: [{ source_ip: "203.0.113.45", alerts: 4 }],
    recent_alerts: [],
    recent_incidents: [],
    ...overrides,
  };
}

export function trendDays(n: number): TrendDay[] {
  const zero: Record<Level, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  return Array.from({ length: n }, (_, i) => ({
    day: `2026-09-${String(28 - n + i).padStart(2, "0")}`,
    alerts: i === n - 1 ? { ...zero, critical: 1, high: 2 } : { ...zero },
    incidents: i === n - 1 ? 1 : 0,
    events: i * 10,
  }));
}

/** The dashboard's API routes, for tests that land on the default page. */
export function dashboardRoutes(overrides: Partial<DashboardSummary> = {}): Routes {
  return {
    "GET /api/dashboard/summary": { body: dashboardSummary(overrides) },
    "GET /api/dashboard/trends": (call) => {
      const days = Number(call.url.searchParams.get("days") ?? 14);
      return { body: { days, items: trendDays(days) } };
    },
  };
}
