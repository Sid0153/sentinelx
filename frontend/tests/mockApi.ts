import { vi } from "vitest";

/** A canned answer for one API route. `NETWORK_ERROR` makes fetch reject like a dead server. */
export interface MockRoute {
  status?: number;
  body?: unknown;
  rawBody?: string;
  headers?: Record<string, string>;
}

export const NETWORK_ERROR = Symbol("network error");

type Routes = Record<string, MockRoute | typeof NETWORK_ERROR>;

/**
 * Replaces fetch. Keys are "METHOD /api/path" (query string ignored). An unmocked route fails
 * the test loudly instead of silently returning nothing.
 */
export function mockApi(routes: Routes) {
  const calls: string[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const key = `${init?.method ?? "GET"} ${url.pathname}`;
    calls.push(key);
    const route = routes[key];
    if (route === undefined) throw new Error(`Unmocked API call: ${key}`);
    if (route === NETWORK_ERROR) throw new TypeError("Failed to fetch");
    // 204 and friends must have a null body, or the Response constructor throws.
    const body = route.rawBody ?? (route.body === undefined ? null : JSON.stringify(route.body));
    return new Response(body, {
      status: route.status ?? 200,
      headers: { "Content-Type": "application/json", ...route.headers },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, setRoute: (key: string, route: MockRoute | typeof NETWORK_ERROR) => {
    routes[key] = route;
  } };
}
