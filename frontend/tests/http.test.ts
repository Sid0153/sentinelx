import { describe, expect, it } from "vitest";

import { ApiError, apiRequest } from "../src/services/http";
import { mockApi, NETWORK_ERROR } from "./mockApi";

async function caught(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("expected the request to fail");
}

describe("apiRequest", () => {
  it("returns the parsed body on success", async () => {
    mockApi({ "GET /api/thing": { body: { value: 42 } } });
    await expect(apiRequest<{ value: number }>("/thing")).resolves.toEqual({ value: 42 });
  });

  it("turns the backend error shape into an ApiError with code and request ID", async () => {
    mockApi({
      "POST /api/thing": {
        status: 409,
        body: {
          error: { code: "conflict", message: "Alert is already resolved", request_id: "r-1234567" },
        },
      },
    });
    const error = await caught(apiRequest("/thing", { method: "POST", body: {} }));
    expect(error.status).toBe(409);
    expect(error.code).toBe("conflict");
    expect(error.message).toBe("Alert is already resolved");
    expect(error.requestId).toBe("r-1234567");
  });

  it("returns the body for statuses the caller accepts", async () => {
    mockApi({ "GET /api/ready": { status: 503, body: { status: "unavailable" } } });
    await expect(apiRequest("/ready", { acceptStatuses: [503] })).resolves.toEqual({
      status: "unavailable",
    });
  });

  it("reports a network failure without leaking browser internals", async () => {
    mockApi({ "GET /api/thing": NETWORK_ERROR });
    const error = await caught(apiRequest("/thing"));
    expect(error.code).toBe("network_error");
    expect(error.status).toBe(0);
  });

  it("sends JSON bodies with a content type", async () => {
    const api = mockApi({ "POST /api/thing": { status: 204 } });
    await expect(apiRequest("/thing", { method: "POST", body: { a: 1 } })).resolves.toBeNull();
    expect(api.calls).toEqual(["POST /api/thing"]);
    const [, init] = (globalThis.fetch as unknown as { mock: { calls: [string, RequestInit][] } })
      .mock.calls[0];
    expect(init.body).toBe('{"a":1}');
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });
});
