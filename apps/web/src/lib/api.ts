/**
 * Client for the ForgeLab API.
 *
 * Live run updates arrive over SSE rather than polling — see the event stream
 * work order (WO-005) for the `/events` endpoint this will subscribe to.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_FORGELAB_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });

  if (!response.ok) {
    throw new ApiError(`Request to ${path} failed`, response.status);
  }

  return (await response.json()) as T;
}

export type ReadinessReport = {
  ready: boolean;
  checks: Record<string, string>;
};

export function getReadiness(): Promise<ReadinessReport> {
  return apiFetch<ReadinessReport>("/readyz", { cache: "no-store" });
}
