import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { mockApi, NETWORK_ERROR } from "./mockApi";
import { renderApp } from "./renderApp";

const HEALTHY = {
  "GET /api/health": { body: { status: "ok", version: "0.1.0" } },
  "GET /api/ready": {
    body: { status: "ok", checks: { database: "up", migrations: "current" } },
  },
};

describe("System status page", () => {
  it("is where the app starts", async () => {
    mockApi({ ...HEALTHY });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "System status" })).toBeInTheDocument();
  });

  it("shows a healthy platform from the live checks", async () => {
    mockApi({ ...HEALTHY });
    renderApp("/status");
    expect(await screen.findByText("Operational")).toBeInTheDocument();
    expect(screen.getByText("Version 0.1.0")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
    expect(screen.getByText("Up to date")).toBeInTheDocument();
  });

  it("reports a database outage from a 503 readiness answer", async () => {
    mockApi({
      ...HEALTHY,
      "GET /api/ready": {
        status: 503,
        body: { status: "unavailable", checks: { database: "down", migrations: "unknown" } },
      },
    });
    renderApp("/status");
    expect(await screen.findByText("Not ready")).toBeInTheDocument();
    expect(screen.getByText("Unreachable")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("reports pending migrations", async () => {
    mockApi({
      ...HEALTHY,
      "GET /api/ready": {
        status: 503,
        body: { status: "unavailable", checks: { database: "up", migrations: "pending" } },
      },
    });
    renderApp("/status");
    expect(await screen.findByText("Migrations pending")).toBeInTheDocument();
  });

  it("shows an error when the API cannot be reached, and recovers on retry", async () => {
    const api = mockApi({ ...HEALTHY, "GET /api/health": NETWORK_ERROR });
    renderApp("/status");
    expect(await screen.findByRole("alert")).toHaveTextContent("API unreachable");

    api.setRoute("GET /api/health", HEALTHY["GET /api/health"]);
    fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    expect(await screen.findByText("Operational")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("treats a gateway error page (backend restarting) as unreachable", async () => {
    mockApi({
      ...HEALTHY,
      "GET /api/health": {
        status: 502,
        rawBody: "<html>Bad Gateway</html>",
        headers: { "Content-Type": "text/html", "X-Request-ID": "gw-12345678" },
      },
    });
    renderApp("/status");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("HTTP 502");
    expect(alert).toHaveTextContent("gw-12345678");
  });
});

describe("Routing", () => {
  it("shows a not-found page for unknown paths", async () => {
    mockApi({});
    renderApp("/no-such-page");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("link", { name: "Go to system status" })).toHaveAttribute(
        "href",
        "/status",
      ),
    );
  });
});
