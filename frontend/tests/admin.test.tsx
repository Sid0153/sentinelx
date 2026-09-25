import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AuditEntry, User } from "../src/types/api";
import { makeUser, mockApi, signedInAs } from "./mockApi";
import { renderApp } from "./renderApp";

const ADMIN = signedInAs("ADMIN");

function page<T>(items: T[]) {
  return { body: { items, total: items.length, limit: 50, offset: 0 } };
}

describe("Users page", () => {
  const analyst = makeUser("ANALYST", { id: "u-2", email: "ana@example.com" });

  it("lists users and keeps admins from changing themselves", async () => {
    mockApi({ ...ADMIN, "GET /api/users": page([makeUser("ADMIN"), analyst]) });
    renderApp("/users");
    expect(await screen.findByText("ana@example.com")).toBeInTheDocument();
    expect(screen.getByLabelText("Role of admin@example.com")).toBeDisabled();
    expect(screen.getByLabelText("Role of ana@example.com")).toBeEnabled();
    expect(screen.getAllByRole("button", { name: "Deactivate" })).toHaveLength(1);
  });

  it("creates a user and reloads the list", async () => {
    let users: User[] = [makeUser("ADMIN")];
    const api = mockApi({
      ...ADMIN,
      "GET /api/users": () => page(users),
      "POST /api/users": (call) => {
        const created = makeUser("VIEWER", { id: "u-3", email: (call.body as User).email });
        users = [...users, created];
        return { status: 201, body: created };
      },
    });
    renderApp("/users");
    await screen.findByRole("form", { name: "Create user" });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@example.com" } });
    fireEvent.change(screen.getByLabelText("Initial password"), {
      target: { value: "a-long-initial-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));

    expect(await screen.findByText("new@example.com")).toBeInTheDocument();
    expect(api.callsTo("POST /api/users")[0].body).toEqual({
      email: "new@example.com",
      password: "a-long-initial-password",
      role: "VIEWER",
    });
  });

  it("shows the server's reason when creation fails", async () => {
    mockApi({
      ...ADMIN,
      "GET /api/users": page([makeUser("ADMIN")]),
      "POST /api/users": {
        status: 409,
        body: {
          error: { code: "conflict", message: "A user with this email already exists", request_id: null },
        },
      },
    });
    renderApp("/users");
    await screen.findByRole("form", { name: "Create user" });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "dup@example.com" } });
    fireEvent.change(screen.getByLabelText("Initial password"), {
      target: { value: "a-long-initial-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already exists");
  });

  it("changes a role and deactivates a user", async () => {
    let current = analyst;
    const api = mockApi({
      ...ADMIN,
      "GET /api/users": () => page([makeUser("ADMIN"), current]),
      "PATCH /api/users/u-2": (call) => {
        current = { ...current, ...(call.body as Partial<User>) };
        return { body: current };
      },
    });
    renderApp("/users");
    fireEvent.change(await screen.findByLabelText("Role of ana@example.com"), {
      target: { value: "VIEWER" },
    });
    await waitFor(() => expect(screen.getByLabelText("Role of ana@example.com")).toHaveValue("VIEWER"));

    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    expect(await screen.findByRole("button", { name: "Reactivate" })).toBeInTheDocument();
    expect(api.callsTo("PATCH /api/users/u-2").map((c) => c.body)).toEqual([
      { role: "VIEWER" },
      { is_active: false },
    ]);
  });
});

describe("Audit page", () => {
  const entry: AuditEntry = {
    id: "a-1",
    occurred_at: "2026-09-25T10:15:30Z",
    action: "LOGIN_FAILED",
    result: "FAILURE",
    actor_id: null,
    actor_label: null,
    entity_type: null,
    entity_id: null,
    client_ip: "203.0.113.9",
    request_id: "r-1",
    details: { reason: "unknown_email" },
  };

  it("shows entries in UTC with their details", async () => {
    mockApi({ ...ADMIN, "GET /api/audit": page([entry]) });
    renderApp("/audit");
    expect(await screen.findByText("2026-09-25 10:15:30 UTC")).toBeInTheDocument();
    expect(screen.getByText("anonymous")).toBeInTheDocument();
    expect(screen.getByText("reason: unknown_email")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.9")).toBeInTheDocument();
  });

  it("filters on the server and keeps the filter in the URL", async () => {
    const api = mockApi({ ...ADMIN, "GET /api/audit": page([entry]) });
    renderApp("/audit");
    await screen.findByText("LOGIN_FAILED", { selector: "td" });
    fireEvent.change(screen.getByLabelText("Result"), { target: { value: "DENIED" } });
    await waitFor(() => expect(api.callsTo("GET /api/audit")).toHaveLength(2));
    expect(api.callsTo("GET /api/audit")[1].url.searchParams.get("result")).toBe("DENIED");
  });

  it("renders hostile detail values as text, not markup", async () => {
    const hostile = { ...entry, details: { note: '<img src=x onerror="alert(1)">' } };
    mockApi({ ...ADMIN, "GET /api/audit": page([hostile]) });
    const { container } = renderApp("/audit");
    expect(await screen.findByText(/note: <img src=x/)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows an empty state when nothing matches", async () => {
    mockApi({ ...ADMIN, "GET /api/audit": page([]) });
    renderApp("/audit");
    expect(await screen.findByText("No entries match these filters.")).toBeInTheDocument();
  });
});

describe("Account page", () => {
  it("changes the password and returns to sign-in", async () => {
    const api = mockApi({ ...signedInAs("VIEWER"), "POST /api/auth/change-password": { status: 204 } });
    renderApp("/settings");
    fireEvent.change(await screen.findByLabelText("Current password"), {
      target: { value: "old-password-12345" },
    });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "new-password-12345" } });
    fireEvent.change(screen.getByLabelText("Repeat new password"), {
      target: { value: "new-password-12345" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(
      await screen.findByText("Password changed. Sign in with your new password."),
    ).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/change-password")[0].body).toEqual({
      current_password: "old-password-12345",
      new_password: "new-password-12345",
    });
  });

  it("checks that the new password was repeated correctly before calling the API", async () => {
    const api = mockApi({ ...signedInAs("VIEWER") });
    renderApp("/settings");
    fireEvent.change(await screen.findByLabelText("Current password"), {
      target: { value: "old-password-12345" },
    });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "new-password-12345" } });
    fireEvent.change(screen.getByLabelText("Repeat new password"), {
      target: { value: "different-password-1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("do not match");
    expect(api.callsTo("POST /api/auth/change-password")).toHaveLength(0);
  });
});
