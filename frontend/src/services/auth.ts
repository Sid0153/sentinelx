import type { AuthOptions, MfaSetup, TokenResponse, User } from "../types/api";
import { apiRequest, refreshSession, tokenStore } from "./http";

/** The second step of a two-factor sign-in: a code from the app, or a recovery code. */
export interface SecondFactor {
  otp?: string;
  recovery_code?: string;
}

/** A right password on a two-factor account fails with ApiError code "mfa_required". */
export async function login(email: string, password: string, second: SecondFactor = {}): Promise<User> {
  const data = await apiRequest<TokenResponse>("/auth/login", {
    method: "POST",
    body: { email, password, ...second },
    anonymous: true,
  });
  tokenStore.set(data.access_token);
  return data.user;
}

/** Whether this deployment offers "Explore as guest" (a public demo). */
export function authOptions(): Promise<AuthOptions> {
  return apiRequest<AuthOptions>("/auth/options", { anonymous: true });
}

/** Signs in as the shared, read-only guest of a public demo. No password. */
export async function guestLogin(): Promise<User> {
  const data = await apiRequest<TokenResponse>("/auth/guest", { method: "POST", anonymous: true });
  tokenStore.set(data.access_token);
  return data.user;
}

/** On page load: the access token is gone, but the refresh cookie may restore the session. */
export async function restoreSession(): Promise<User> {
  return (await refreshSession()).user;
}

export async function logout(): Promise<void> {
  try {
    await apiRequest<null>("/auth/logout", { method: "POST", anonymous: true });
  } finally {
    tokenStore.set(null);
  }
}

export function changePassword(currentPassword: string, newPassword: string): Promise<null> {
  return apiRequest<null>("/auth/change-password", {
    method: "POST",
    body: { current_password: currentPassword, new_password: newPassword },
  });
}

export function currentUser(): Promise<User> {
  return apiRequest<User>("/auth/me");
}

export function startMfaSetup(): Promise<MfaSetup> {
  return apiRequest<MfaSetup>("/auth/mfa/setup", { method: "POST" });
}

export function enableMfa(code: string): Promise<{ recovery_codes: string[] }> {
  return apiRequest<{ recovery_codes: string[] }>("/auth/mfa/enable", {
    method: "POST",
    body: { code },
  });
}

export function disableMfa(password: string, code: string): Promise<null> {
  return apiRequest<null>("/auth/mfa/disable", { method: "POST", body: { password, code } });
}
