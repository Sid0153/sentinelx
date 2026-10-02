import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, onTestFinished, vi } from "vitest";

import { dashboardRoutes } from "./fixtures";
import { mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

describe("A page that fails to render", () => {
  afterEach(() => vi.restoreAllMocks());

  it("shows a message instead of a blank app, and other pages still work", async () => {
    // React reports the caught error to the console and, in development, to window "error".
    vi.spyOn(console, "error").mockImplementation(() => {});
    const quiet = (event: ErrorEvent) => event.preventDefault();
    window.addEventListener("error", quiet);
    onTestFinished(() => window.removeEventListener("error", quiet));
    mockApi({
      ...signedInAs("VIEWER"),
      ...dashboardRoutes(),
      // A response of an unexpected shape: the page cannot draw it.
      "GET /api/dashboard/summary": { body: { unexpected: true } },
      "GET /api/alerts": { body: { items: [], total: 0, limit: 50, offset: 0 } },
    });
    renderApp("/dashboard");

    expect(await screen.findByRole("alert")).toHaveTextContent("This page could not be shown.");
    fireEvent.click(screen.getByRole("link", { name: "Alerts" }));
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.queryByText("This page could not be shown.")).not.toBeInTheDocument();
  });
});
