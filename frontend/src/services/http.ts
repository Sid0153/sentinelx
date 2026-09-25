import type { ApiErrorBody, TokenResponse } from "../types/api";

/** Every failed API call becomes an ApiError with the backend's error code and request ID. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ---------- session state ----------

// The access token lives only in this variable: not in localStorage or sessionStorage, so a
// cross-site-scripting bug cannot read it back later. A page reload clears it, and the
// httpOnly refresh cookie (which JavaScript cannot read at all) is used to get a new one.
let accessToken: string | null = null;
let sessionExpiredListener: (() => void) | null = null;

export const tokenStore = {
  get: (): string | null => accessToken,
  set: (token: string | null): void => {
    accessToken = token;
  },
};

/** Called when the session ended and could not be renewed (the user must sign in again). */
export function onSessionExpired(listener: (() => void) | null): void {
  sessionExpiredListener = listener;
}

// ---------- requests ----------

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Record<string, string | number | string[] | undefined>;
  signal?: AbortSignal;
  /** Non-2xx statuses whose body is a normal answer, e.g. 503 from the readiness check. */
  acceptStatuses?: number[];
  /** Auth endpoints: no bearer token, and a 401 is an answer, not an expired session. */
  anonymous?: boolean;
}

function isErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = (value as { error: unknown }).error;
  return typeof error === "object" && error !== null && "code" in error && "message" in error;
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function buildUrl(path: string, query: RequestOptions["query"]): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === "") continue;
    for (const item of Array.isArray(value) ? value : [value]) params.append(key, String(item));
  }
  const search = params.toString();
  return `/api${path}${search ? `?${search}` : ""}`;
}

async function send(path: string, options: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (!options.anonymous && accessToken) headers.Authorization = `Bearer ${accessToken}`;
  try {
    return await fetch(buildUrl(path, options.query), {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "network_error", "The SentinelX API could not be reached.");
  }
}

async function toResult<T>(response: Response, options: RequestOptions): Promise<T> {
  const body = await readJson(response);
  if (response.ok || options.acceptStatuses?.includes(response.status)) {
    return body as T;
  }
  if (isErrorBody(body)) {
    throw new ApiError(
      response.status,
      body.error.code,
      body.error.message,
      body.error.request_id,
    );
  }
  // Not our error shape: a proxy or gateway answered (e.g. nginx 502 while the API restarts).
  throw new ApiError(
    response.status,
    "unexpected_response",
    `Unexpected response from the server (HTTP ${response.status}).`,
    response.headers.get("X-Request-ID"),
  );
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  let response = await send(path, options);
  if (response.status === 401 && !options.anonymous) {
    // The access token expired (15 minutes). Renew it once from the refresh cookie, then
    // repeat the request. If that fails the session is over.
    try {
      await refreshSession();
    } catch {
      sessionExpiredListener?.();
      return toResult<T>(response, options);
    }
    response = await send(path, options);
  }
  return toResult<T>(response, options);
}

// ---------- refresh ----------

async function requestRefresh(): Promise<TokenResponse> {
  try {
    const data = await toResult<TokenResponse>(
      await send("/auth/refresh", { method: "POST", anonymous: true }),
      {},
    );
    accessToken = data.access_token;
    return data;
  } catch (error) {
    accessToken = null;
    throw error;
  }
}

// The backend rotates the refresh token on every use and treats a replayed one as theft
// (all sessions end). Concurrent refreshes must therefore never send the same cookie twice:
// within a tab they share one request, and across tabs the Web Locks API runs them one after
// the other (the cookie jar is shared, so the second tab sends the already-rotated cookie).
let inFlight: Promise<TokenResponse> | null = null;

export function refreshSession(): Promise<TokenResponse> {
  if (inFlight === null) {
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    // The lock is held until the callback's promise settles, and request() resolves with its
    // value. TypeScript's DOM types model that as a nested promise; .then() flattens it.
    const run: Promise<TokenResponse> = locks
      ? locks.request("sentinelx-refresh", () => requestRefresh()).then((result) => result)
      : requestRefresh();
    const shared = run.finally(() => {
      inFlight = null;
    });
    inFlight = shared;
    return shared;
  }
  return inFlight;
}
