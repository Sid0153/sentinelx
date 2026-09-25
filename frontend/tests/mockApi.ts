import { vi } from "vitest";

import type { Role, User } from "../src/types/api";

/** A canned answer for one API route. `NETWORK_ERROR` makes fetch reject like a dead server. */
export interface MockRoute {
  status?: number;
  body?: unknown;
  rawBody?: string;
  headers?: Record<string, string>;
}

export const NETWORK_ERROR = Symbol("network error");

export interface RecordedCall {
  key: string;
  url: URL;
  body: unknown;
  authorization: string | null;
}

type Handler = MockRoute | typeof NETWORK_ERROR | ((call: RecordedCall) => MockRoute);
export type Routes = Record<string, Handler>;

/**
 * Replaces fetch. Keys are "METHOD /api/path" (query string ignored; it is available in
 * `calls`). An unmocked route fails the test loudly instead of silently returning nothing.
 */
export function mockApi(routes: Routes) {
  const calls: RecordedCall[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const key = `${init?.method ?? "GET"} ${url.pathname}`;
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const call: RecordedCall = {
      key,
      url,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      authorization: headers.Authorization ?? null,
    };
    calls.push(call);
    const handler = routes[key];
    if (handler === undefined) throw new Error(`Unmocked API call: ${key}`);
    if (handler === NETWORK_ERROR) throw new TypeError("Failed to fetch");
    const route = typeof handler === "function" ? handler(call) : handler;
    // 204 and friends must have a null body, or the Response constructor throws.
    const body = route.rawBody ?? (route.body === undefined ? null : JSON.stringify(route.body));
    return new Response(body, {
      status: route.status ?? 200,
      headers: { "Content-Type": "application/json", ...route.headers },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return {
    calls,
    callsTo: (key: string) => calls.filter((c) => c.key === key),
    setRoute: (key: string, handler: Handler) => {
      routes[key] = handler;
    },
  };
}

export function makeUser(role: Role, overrides: Partial<User> = {}): User {
  return {
    id: `user-${role.toLowerCase()}`,
    email: `${role.toLowerCase()}@example.com`,
    role,
    is_active: true,
    created_at: "2026-09-01T08:00:00Z",
    last_login_at: "2026-09-25T09:30:00Z",
    ...overrides,
  };
}

export function unauthorized(message = "Not authenticated"): MockRoute {
  return {
    status: 401,
    body: { error: { code: "unauthorized", message, request_id: "req-00000001" } },
  };
}

/** Routes for a browser whose refresh cookie restores a session as `role`. */
export function signedInAs(role: Role, token = "access-token-1"): Routes {
  return {
    "POST /api/auth/refresh": {
      body: { access_token: token, expires_in: 900, user: makeUser(role) },
    },
    "POST /api/auth/logout": { status: 204 },
  };
}

/** Routes for a browser without a session. */
export function signedOut(): Routes {
  return { "POST /api/auth/refresh": unauthorized("No session") };
}

export const HEALTHY: Routes = {
  "GET /api/health": { body: { status: "ok", version: "0.1.0" } },
  "GET /api/ready": {
    body: { status: "ok", checks: { database: "up", migrations: "current" } },
  },
};
