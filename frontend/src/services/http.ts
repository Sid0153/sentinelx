import type { ApiErrorBody } from "../types/api";

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

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
  /** Non-2xx statuses whose body is a normal answer, e.g. 503 from the readiness check. */
  acceptStatuses?: number[];
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

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
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
