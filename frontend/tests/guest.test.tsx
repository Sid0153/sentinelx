import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { dashboardRoutes } from "./fixtures";
import { makeUser, mockApi, signedInAs, signedOut } from "./mockApi";
import { renderApp } from "./renderApp";

const GUEST = makeUser("VIEWER", { email: "guest@sentinelx.example", is_guest: true });

describe("A public demo's guest access", () => {
  it("is not offered unless the server says so", async () => {
    mockApi({ ...signedOut(), "GET /api/auth/options": { body: { guest_access: false } } });
    renderApp("/");
    await screen.findByRole("heading", { name: "Sign in" });
    expect(screen.queryByRole("button", { name: /Explore as guest/ })).not.toBeInTheDocument();
  });

  it("signs a visitor in as the read-only guest, and says so on every page", async () => {
    const api = mockApi({
      ...signedOut(),
      ...dashboardRoutes(),
      "GET /api/auth/options": { body: { guest_access: true } },
      "POST /api/auth/guest": { body: { access_token: "t-guest", expires_in: 900, user: GUEST } },
    });
    renderApp("/");
    fireEvent.click(await screen.findByRole("button", { name: "Explore as guest (read-only)" }));

    expect(await screen.findByRole("heading", { name: "SOC dashboard" })).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/guest")).toHaveLength(1);
    expect(api.callsTo("GET /api/dashboard/summary")[0].authorization).toBe("Bearer t-guest");
    expect(screen.getByRole("note")).toHaveTextContent("read-only guest, and all data is SIMULATED");
  });

  it("explains when guest access is unavailable", async () => {
    mockApi({
      ...signedOut(),
      "GET /api/auth/options": { body: { guest_access: true } },
      "POST /api/auth/guest": { status: 403, body: { error: { code: "forbidden", message: "Guest access is not available", request_id: "r" } } },
    });
    renderApp("/");
    fireEvent.click(await screen.findByRole("button", { name: "Explore as guest (read-only)" }));
    expect(await screen.findByText("Guest access is not available right now.")).toBeInTheDocument();
  });

  it("hides the password and two-factor settings from the shared account", async () => {
    const routes = signedInAs("VIEWER");
    mockApi({ ...routes, "POST /api/auth/refresh": { body: { access_token: "t", expires_in: 900, user: GUEST } } });
    renderApp("/settings");
    expect(await screen.findByText(/shared guest account/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
  });
});
