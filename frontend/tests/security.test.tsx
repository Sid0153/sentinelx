// Phase 13 hardening in the UI: two-factor sign-in, forced password change after an admin
// reset, the admin resets, and the audit chain check.
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HEALTHY, makeUser, mockApi, signedInAs, signedOut, unauthorized } from "./mockApi";
import { renderApp } from "./renderApp";

const MFA_REQUIRED = {
  status: 401,
  body: { error: { code: "mfa_required", message: "Enter the code", request_id: null } },
};

function fillLogin(email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Two-factor sign-in", () => {
  it("asks for the code after the password and sends both", async () => {
    const api = mockApi({
      ...signedOut(),
      ...HEALTHY,
      "POST /api/auth/login": (call) =>
        (call.body as { otp?: string }).otp === "123456"
          ? { body: { access_token: "t-1", expires_in: 900, user: makeUser("ANALYST", { mfa_enabled: true }) } }
          : MFA_REQUIRED,
    });
    renderApp("/status");
    await screen.findByRole("heading", { name: "Sign in" });
    fillLogin("analyst@example.com", "correct-horse-battery-staple");

    expect(await screen.findByRole("heading", { name: "Two-factor sign-in" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument(); // not an error, a next step
    fireEvent.change(screen.getByLabelText("Code from your authenticator app"), {
      target: { value: " 123456 " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/login")[1].body).toEqual({
      email: "analyst@example.com",
      password: "correct-horse-battery-staple",
      otp: "123456",
    });
  });

  it("says when the code is wrong, and accepts a recovery code instead", async () => {
    const api = mockApi({
      ...signedOut(),
      ...HEALTHY,
      "POST /api/auth/login": (call) => {
        const body = call.body as { otp?: string; recovery_code?: string };
        if (body.recovery_code === "abcde-12345") {
          return { body: { access_token: "t-1", expires_in: 900, user: makeUser("VIEWER") } };
        }
        return body.otp ? unauthorized("Invalid email or password") : MFA_REQUIRED;
      },
    });
    renderApp("/status");
    await screen.findByRole("heading", { name: "Sign in" });
    fillLogin("viewer@example.com", "correct-horse-battery-staple");
    await screen.findByRole("heading", { name: "Two-factor sign-in" });

    fireEvent.change(screen.getByLabelText("Code from your authenticator app"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That code is not correct.");

    fireEvent.click(screen.getByRole("button", { name: "Use a recovery code" }));
    fireEvent.change(screen.getByLabelText("Recovery code"), { target: { value: "abcde-12345" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("viewer@example.com")).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/login").at(-1)!.body).toMatchObject({ recovery_code: "abcde-12345" });
  });

  it("is turned on from the account page, showing the recovery codes once", async () => {
    const codes = Array.from({ length: 10 }, (_, i) => `code${i}-xxxxx`);
    const api = mockApi({
      ...signedInAs("VIEWER"),
      "POST /api/auth/mfa/setup": {
        body: { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/SentinelX:viewer@example.com?secret=JBSWY3DPEHPK3PXP" },
      },
      "POST /api/auth/mfa/enable": { body: { recovery_codes: codes } },
      "GET /api/auth/me": { body: makeUser("VIEWER", { mfa_enabled: true }) },
    });
    renderApp("/settings");
    fireEvent.click(await screen.findByRole("button", { name: "Set up two-factor sign-in" }));
    expect(await screen.findByLabelText("Setup key")).toHaveTextContent("JBSWY3DPEHPK3PXP");
    fireEvent.change(screen.getByLabelText("Code from the app"), { target: { value: "654321" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));

    const list = await screen.findByRole("list", { name: "Recovery codes" });
    expect(list.querySelectorAll("li")).toHaveLength(10);
    expect(api.callsTo("POST /api/auth/mfa/enable")[0].body).toEqual({ code: "654321" });
    fireEvent.click(screen.getByRole("button", { name: "I saved them" }));
    // The codes are gone; the panel now offers turning it off (password + code).
    expect(await screen.findByRole("button", { name: "Turn off" })).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Recovery codes" })).not.toBeInTheDocument();
  });

  it("is turned off only with the password and a code", async () => {
    const api = mockApi({
      ...signedInAs("VIEWER"),
      "POST /api/auth/refresh": {
        body: { access_token: "t", expires_in: 900, user: makeUser("VIEWER", { mfa_enabled: true }) },
      },
      "POST /api/auth/mfa/disable": { status: 204 },
      "GET /api/auth/me": { body: makeUser("VIEWER") },
    });
    renderApp("/settings");
    fireEvent.click(await screen.findByRole("button", { name: "Turn off" }));
    // Required fields: nothing is sent while they are empty.
    expect(api.callsTo("POST /api/auth/mfa/disable")).toHaveLength(0);
    fireEvent.change(screen.getAllByLabelText("Password").at(-1)!, { target: { value: "my-password-123" } });
    fireEvent.change(screen.getByLabelText("Code from the app or a recovery code"), { target: { value: "111222" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    expect(await screen.findByRole("button", { name: "Set up two-factor sign-in" })).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/mfa/disable")[0].body).toEqual({
      password: "my-password-123",
      code: "111222",
    });
  });
});

describe("Forced password change", () => {
  it("shows only the password form until the temporary password is replaced", async () => {
    const api = mockApi({
      "POST /api/auth/refresh": {
        body: { access_token: "t", expires_in: 900, user: makeUser("ANALYST", { must_change_password: true }) },
      },
      "POST /api/auth/logout": { status: 204 },
      "POST /api/auth/change-password": { status: 204 },
    });
    renderApp("/alerts");
    expect(await screen.findByRole("heading", { name: "Choose a new password" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Main" })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Temporary password"), { target: { value: "temp-password-xyz" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "my-own-new-password" } });
    fireEvent.change(screen.getByLabelText("Repeat new password"), { target: { value: "my-own-new-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("Password changed. Sign in with your new password.")).toBeInTheDocument();
    expect(api.callsTo("POST /api/auth/change-password")[0].body).toEqual({
      current_password: "temp-password-xyz",
      new_password: "my-own-new-password",
    });
  });
});

describe("Admin resets", () => {
  const ana = makeUser("ANALYST", { id: "u-2", email: "ana@example.com", mfa_enabled: true });
  const users = { body: { items: [makeUser("ADMIN"), ana], total: 2, limit: 25, offset: 0 } };

  it("resets a password and shows the temporary one once", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const api = mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/users": users,
      "POST /api/users/u-2/reset-password": { body: { temporary_password: "temporary-from-admin" } },
    });
    renderApp("/users");
    await screen.findByText("ana@example.com");
    // Not offered for one's own account: one reset button, for ana.
    const buttons = screen.getAllByRole("button", { name: "Reset password" });
    expect(buttons).toHaveLength(1);
    fireEvent.click(buttons[0]);
    expect(await screen.findByText("temporary-from-admin")).toBeInTheDocument();
    expect(api.callsTo("POST /api/users/u-2/reset-password")).toHaveLength(1);
  });

  it("asks before resetting two-factor sign-in and does nothing when cancelled", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const api = mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/users": users,
      "POST /api/users/u-2/reset-mfa": { body: { ...ana, mfa_enabled: false } },
    });
    renderApp("/users");
    fireEvent.click(await screen.findByRole("button", { name: "Reset 2FA" }));
    expect(confirm).toHaveBeenCalledOnce();
    expect(api.callsTo("POST /api/users/u-2/reset-mfa")).toHaveLength(0);

    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Reset 2FA" }));
    await waitFor(() => expect(api.callsTo("POST /api/users/u-2/reset-mfa")).toHaveLength(1));
  });
});

describe("Audit chain check", () => {
  it("says loudly when the chain is broken", async () => {
    mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/audit": { body: { items: [], total: 0, limit: 50, offset: 0 } },
      "GET /api/audit/integrity": {
        body: { intact: false, chained: 40, legacy: 3, first_broken_seq: 17, head_seq: 43, head_hash: "cd".repeat(32) },
      },
    });
    renderApp("/audit");
    const status = await screen.findByRole("status", { name: "Audit log integrity" });
    expect(status).toHaveTextContent("Hash chain BROKEN at entry 17");
    expect(status).toHaveTextContent("3 older entries predate the chain");
  });

  it("reports an intact chain with its head for comparison with the log", async () => {
    mockApi({
      ...signedInAs("ADMIN"),
      "GET /api/audit": { body: { items: [], total: 0, limit: 50, offset: 0 } },
      "GET /api/audit/integrity": {
        body: { intact: true, chained: 12, legacy: 0, first_broken_seq: null, head_seq: 12, head_hash: "ef".repeat(32) },
      },
    });
    renderApp("/audit");
    const status = await screen.findByRole("status", { name: "Audit log integrity" });
    expect(status).toHaveTextContent("Hash chain intact: 12 entries verified.");
    expect(status).toHaveTextContent("ef".repeat(32));
  });
});
