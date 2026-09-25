import type { TokenResponse, User } from "../types/api";
import { apiRequest, refreshSession, tokenStore } from "./http";

export async function login(email: string, password: string): Promise<User> {
  const data = await apiRequest<TokenResponse>("/auth/login", {
    method: "POST",
    body: { email, password },
    anonymous: true,
  });
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
