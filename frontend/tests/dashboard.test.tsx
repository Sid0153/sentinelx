import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { dashboardRoutes } from "./fixtures";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

const SIGNED_IN = signedInAs("VIEWER");

function tile(label: string) {
  return screen.getByText(label, { selector: "div" }).parentElement as HTMLElement;
}

describe("SOC dashboard", () => {
  it("is where a signed-in user starts", async () => {
    mockApi({ ...SIGNED_IN, ...dashboardRoutes() });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "SOC dashboard" })).toBeInTheDocument();
  });

  it("shows the counts from the API, linking each to its page", async () => {
    mockApi({ ...SIGNED_IN, ...dashboardRoutes() });
    renderApp("/dashboard");
    await screen.findByRole("heading", { name: "SOC dashboard" });

    expect(within(tile("Records processed")).getByText("1,240")).toBeInTheDocument();
    expect(within(tile("Events stored")).getByText("312 today")).toBeInTheDocument();
    expect(tile("Critical alerts")).toHaveAttribute("href", "/alerts?severity=critical");
    expect(within(tile("Critical alerts")).getByText("2")).toBeInTheDocument();
    expect(within(tile("Open incidents")).getByText("1 under investigation")).toBeInTheDocument();
    expect(within(tile("Active rules")).getByText("of 9 in the library")).toBeInTheDocument();

    const bars = screen.getByRole("list", { name: "Open alerts by severity" });
    expect(within(bars).getByText("medium").parentElement).toHaveTextContent("4");
    expect(screen.getByRole("link", { name: /AUTH-001 Repeated failed logons/ })).toHaveAttribute(
      "href",
      "/detections/AUTH-001",
    );
    expect(screen.getByRole("link", { name: "203.0.113.45" })).toHaveAttribute(
      "href",
      "/events?source_ip=203.0.113.45&range=7d",
    );
    // Nothing was ingested? The empty-state help is not shown when there is data.
    expect(screen.queryByText(/No data yet/)).not.toBeInTheDocument();
  });

  it("explains an empty system instead of showing bare zeros", async () => {
    mockApi({
      ...SIGNED_IN,
      ...dashboardRoutes({ records_processed: 0, events_stored: 0, top_rules: [], top_source_ips: [] }),
    });
    renderApp("/dashboard");
    expect(await screen.findByText(/No data yet/)).toBeInTheDocument();
    expect(screen.getByText("No alerts in the last 7 days.")).toBeInTheDocument();
  });

  it("says how many open alerts are simulated", async () => {
    mockApi({ ...SIGNED_IN, ...dashboardRoutes({ open_alerts_simulated: 5 }) });
    renderApp("/dashboard");
    expect(await screen.findByText(/5 of 9 open alerts come from simulated demo records/)).toBeInTheDocument();
  });

  it("draws the trends with a table view of the same numbers, and changes the period", async () => {
    const api = mockApi({ ...SIGNED_IN, ...dashboardRoutes() });
    renderApp("/dashboard");
    const chart = await screen.findByRole("img", { name: /Alerts created: peak 3 on one day/ });
    expect(chart).toBeInTheDocument();
    expect(api.callsTo("GET /api/dashboard/trends")[0].url.searchParams.get("days")).toBe("14");

    // Every value in the chart is also in the table view.
    const table = screen.getAllByRole("table", { hidden: true })[0];
    const lastDay = within(table).getByText("2026-09-27").closest("tr") as HTMLElement;
    expect(lastDay).toHaveTextContent("2026-09-27" + "1" + "2" + "0" + "0");

    // Keyboard focus on a day shows its values.
    fireEvent.focus(screen.getAllByRole("button", { name: /^2026-09-27: critical 1, high 2/ })[0]);
    expect(screen.getByRole("status")).toHaveTextContent("critical: 1");

    fireEvent.change(screen.getByLabelText("Period"), { target: { value: "30" } });
    await waitFor(() => expect(api.callsTo("GET /api/dashboard/trends")).toHaveLength(2));
    expect(api.callsTo("GET /api/dashboard/trends")[1].url.searchParams.get("days")).toBe("30");
  });

  it("shows an error from the API", async () => {
    mockApi({
      ...SIGNED_IN,
      "GET /api/dashboard/summary": {
        status: 500,
        body: { error: { code: "internal_error", message: "Something failed.", request_id: "r-1" } },
      },
    });
    renderApp("/dashboard");
    expect(await screen.findByRole("alert")).toHaveTextContent("Something failed.");
  });
});
