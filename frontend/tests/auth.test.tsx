import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { HEALTHY, makeUser, mockApi, signedInAs, signedOut, unauthorized } from "./mockApi";
import { renderApp } from "./renderApp";

function fillLogin(email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("Sign-in", () => {
  it("sends a visitor without a session to the login page", async () => {
    mockApi(signedOut());
    renderApp("/status");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Main" })).not.toBeInTheDocument();
  });

  it("restores the session from the refresh cookie on page load", async () => {
    mockApi({ ...signedInAs("ANALYST"), ...HEALTHY });
    renderApp("/status");
    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();
  });

  it("signs in and returns to the page the user asked for", async () => {
    const api = mockApi({
      ...signedOut(),
      ...HEALTHY,
      "POST /api/auth/login": {
        body: { access_token: "t-1", expires_in: 900, user: makeUser("ADMIN") },
      },
      "GET /api/users": { body: { items: [], total: 0, limit: 25, offset: 0 } },
    });
    renderApp("/users");
    await screen.findByRole("heading", { name: "Sign in" });
    fillLogin("admin@example.com", "correct-horse-battery-staple");

    expect(await screen.findByRole("heading", { name: "Users" })).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/login")[0].body).toEqual({
      email: "admin@example.com",
      password: "correct-horse-battery-staple",
    });
    expect(api.callsTo("GET /api/users")[0].authorization).toBe("Bearer t-1");
  });

  it("shows one generic message for wrong credentials and clears the password", async () => {
    mockApi({
      ...signedOut(),
      "POST /api/auth/login": unauthorized("Invalid email or password"),
    });
    renderApp("/login");
    await screen.findByRole("heading", { name: "Sign in" });
    fillLogin("someone@example.com", "wrong-password-123");
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password.");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("explains the rate limit", async () => {
    mockApi({
      ...signedOut(),
      "POST /api/auth/login": {
        status: 429,
        body: { error: { code: "rate_limited", message: "Too many", request_id: null } },
      },
    });
    renderApp("/login");
    await screen.findByRole("heading", { name: "Sign in" });
    fillLogin("someone@example.com", "wrong-password-123");
    expect(await screen.findByRole("alert")).toHaveTextContent("Too many attempts");
  });

  it("never redirects to another site after sign-in", async () => {
    mockApi({
      ...signedOut(),
      ...HEALTHY,
      "POST /api/auth/login": {
        body: { access_token: "t-1", expires_in: 900, user: makeUser("VIEWER") },
      },
    });
    renderApp("/login");
    await screen.findByRole("heading", { name: "Sign in" });
    fillLogin("viewer@example.com", "correct-horse-battery-staple");
    // No "from" state: lands on the default page inside the app.
    expect(await screen.findByRole("heading", { name: "System status" })).toBeInTheDocument();
  });

  it("signs out, telling the server to end the session", async () => {
    const api = mockApi({ ...signedInAs("VIEWER"), ...HEALTHY });
    renderApp("/status");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByText("You have signed out.")).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/logout")).toHaveLength(1);
  });

  it("returns to sign-in with a notice when the session cannot be renewed", async () => {
    let refreshes = 0;
    mockApi({
      ...HEALTHY,
      "POST /api/auth/refresh": () => {
        refreshes += 1;
        return refreshes === 1
          ? { body: { access_token: "t-1", expires_in: 900, user: makeUser("ADMIN") } }
          : unauthorized("Invalid or expired session");
      },
      "GET /api/users": unauthorized(),
    });
    renderApp("/users");
    expect(
      await screen.findByText("Your session ended. Sign in again to continue."),
    ).toBeInTheDocument();
  });
});

describe("Role-aware navigation", () => {
  it("shows admin pages only to admins", async () => {
    mockApi({ ...signedInAs("ANALYST"), ...HEALTHY });
    renderApp("/status");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Status" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Audit log" })).not.toBeInTheDocument();
  });

  it("tells a non-admin who opens an admin URL that the page needs another role", async () => {
    const api = mockApi({ ...signedInAs("VIEWER") });
    renderApp("/audit");
    expect(await screen.findByRole("heading", { name: "Not authorized" })).toBeInTheDocument();
    // The page never asked the API for data it would be refused.
    expect(api.callsTo("GET /api/audit")).toHaveLength(0);
  });
});
