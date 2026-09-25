import { describe, expect, it, vi } from "vitest";

import { ApiError, apiRequest, onSessionExpired, refreshSession, tokenStore } from "../src/services/http";
import { makeUser, mockApi, NETWORK_ERROR, unauthorized } from "./mockApi";

async function caught(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("expected the request to fail");
}

const REFRESHED = {
  body: { access_token: "fresh-token", expires_in: 900, user: makeUser("ANALYST") },
};

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

  it("sends JSON bodies, query parameters and the bearer token", async () => {
    tokenStore.set("token-abc");
    const api = mockApi({ "POST /api/thing": { status: 204 } });
    await expect(
      apiRequest("/thing", {
        method: "POST",
        body: { a: 1 },
        query: { action: ["A", "B"], empty: "", missing: undefined, offset: 0 },
      }),
    ).resolves.toBeNull();
    const [call] = api.calls;
    expect(call.body).toEqual({ a: 1 });
    expect(call.authorization).toBe("Bearer token-abc");
    expect(call.url.search).toBe("?action=A&action=B&offset=0");
  });

  it("renews an expired access token once and repeats the request", async () => {
    tokenStore.set("expired-token");
    const api = mockApi({
      "GET /api/thing": (call) =>
        call.authorization === "Bearer fresh-token" ? { body: { ok: true } } : unauthorized(),
      "POST /api/auth/refresh": REFRESHED,
    });
    await expect(apiRequest("/thing")).resolves.toEqual({ ok: true });
    expect(api.calls.map((c) => c.key)).toEqual([
      "GET /api/thing",
      "POST /api/auth/refresh",
      "GET /api/thing",
    ]);
    expect(api.callsTo("POST /api/auth/refresh")[0].authorization).toBeNull();
    expect(tokenStore.get()).toBe("fresh-token");
  });

  it("ends the session when the token cannot be renewed", async () => {
    tokenStore.set("expired-token");
    const expired = vi.fn();
    onSessionExpired(expired);
    mockApi({
      "GET /api/thing": unauthorized(),
      "POST /api/auth/refresh": unauthorized("Invalid or expired session"),
    });
    const error = await caught(apiRequest("/thing"));
    expect(error.status).toBe(401);
    expect(expired).toHaveBeenCalledOnce();
    expect(tokenStore.get()).toBeNull();
  });

  it("does not try to refresh for auth endpoints (a 401 there is the answer)", async () => {
    const api = mockApi({ "POST /api/auth/login": unauthorized("Invalid email or password") });
    const error = await caught(
      apiRequest("/auth/login", { method: "POST", body: {}, anonymous: true }),
    );
    expect(error.message).toBe("Invalid email or password");
    expect(api.calls).toHaveLength(1);
  });
});

describe("refreshSession", () => {
  it("shares one request between concurrent callers (a replayed token ends all sessions)", async () => {
    const api = mockApi({ "POST /api/auth/refresh": REFRESHED });
    const [a, b] = await Promise.all([refreshSession(), refreshSession()]);
    expect(a).toBe(b);
    expect(api.callsTo("POST /api/auth/refresh")).toHaveLength(1);
  });
});

/**
 * A stand-in for navigator.locks that behaves like the real lock manager for one name: the
 * lock is held until the callback's promise settles, waiters run one at a time, and
 * request() resolves with the callback's result. jsdom does not provide the Web Locks API.
 */
function fakeLockManager() {
  const log: string[] = [];
  let tail: Promise<unknown> = Promise.resolve();
  let held = false;
  const request = vi.fn((name: string, callback: () => Promise<unknown>) => {
    const run = tail.then(async () => {
      held = true;
      log.push(`acquire ${name}`);
      try {
        return await callback();
      } finally {
        held = false;
        log.push(`release ${name}`);
      }
    });
    tail = run.catch(() => undefined);
    return run;
  });
  return { request, log, isHeld: () => held };
}

describe("refreshSession across tabs (Web Locks)", () => {
  it("renews the session while holding the shared lock, and resolves with the token", async () => {
    const locks = fakeLockManager();
    vi.stubGlobal("navigator", { ...navigator, locks });
    let heldDuringRequest = false;
    mockApi({
      "POST /api/auth/refresh": () => {
        heldDuringRequest = locks.isHeld();
        return REFRESHED;
      },
    });

    const result = await refreshSession();

    // The resolved value is the token response itself, not a nested promise.
    expect(result.access_token).toBe("fresh-token");
    expect(tokenStore.get()).toBe("fresh-token");
    expect(heldDuringRequest).toBe(true);
    expect(locks.request).toHaveBeenCalledWith("sentinelx-refresh", expect.any(Function));
    expect(locks.log).toEqual(["acquire sentinelx-refresh", "release sentinelx-refresh"]);
  });

  it("releases the lock when the refresh fails, so the next attempt can run", async () => {
    const locks = fakeLockManager();
    vi.stubGlobal("navigator", { ...navigator, locks });
    const api = mockApi({ "POST /api/auth/refresh": unauthorized("No session") });

    await expect(refreshSession()).rejects.toBeInstanceOf(ApiError);
    api.setRoute("POST /api/auth/refresh", REFRESHED);
    await expect(refreshSession()).resolves.toMatchObject({ access_token: "fresh-token" });

    expect(locks.log).toEqual([
      "acquire sentinelx-refresh",
      "release sentinelx-refresh",
      "acquire sentinelx-refresh",
      "release sentinelx-refresh",
    ]);
  });

  it("serializes refreshes from two tabs, so the second sends the rotated cookie", async () => {
    // Two tabs share the cookie jar but not this module's in-flight promise. Simulate the
    // second tab by going through the lock manager directly, as its own module would.
    const locks = fakeLockManager();
    vi.stubGlobal("navigator", { ...navigator, locks });
    // The browser's cookie jar: a request carries the value current when it is sent, and the
    // rotated value only arrives with the response (Set-Cookie), a round trip later.
    let cookie = "cookie-1";
    const presented: string[] = [];
    mockApi({
      "POST /api/auth/refresh": () => {
        presented.push(cookie);
        const rotated = `cookie-${presented.length + 1}`;
        setTimeout(() => {
          cookie = rotated;
        }, 20);
        return { ...REFRESHED, delayMs: 20 };
      },
    });

    const otherTab = locks.request("sentinelx-refresh", () =>
      fetch("/api/auth/refresh", { method: "POST" }),
    );
    await Promise.all([refreshSession(), otherTab]);

    // Each cookie value was presented exactly once: no replay, so no theft alarm.
    expect(presented).toEqual(["cookie-1", "cookie-2"]);
  });
});
