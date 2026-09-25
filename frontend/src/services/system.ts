import type { HealthResponse, ReadinessResponse } from "../types/api";
import { apiRequest } from "./http";

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return apiRequest<HealthResponse>("/health", { signal });
}

/** 503 is a normal answer here: it says which dependency is not ready. */
export function getReadiness(signal?: AbortSignal): Promise<ReadinessResponse> {
  return apiRequest<ReadinessResponse>("/ready", { signal, acceptStatuses: [503] });
}
