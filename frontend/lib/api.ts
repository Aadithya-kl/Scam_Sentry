import type { HealthResponse, PredictResponse } from "./types";

/**
 * Base URL of the FastAPI backend. NEXT_PUBLIC_* variables are inlined at
 * build time, so set it in `.env.local` (dev) or as a Docker build arg.
 */
export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/+$/, "");

const REQUEST_TIMEOUT_MS = 20_000;

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ValidationIssue {
  msg?: string;
}

async function readErrorMessage(response: Response): Promise<string> {
  try {
    const body: any = await response.json();
    
    // Support FastAPI standard HTTPExceptions
    if (body.detail && typeof body.detail === "string") return body.detail;
    
    // Support our custom global exception envelope: {"error": {"message": "..."}}
    if (body.error && typeof body.error.message === "string") {
      if (body.error.details && Array.isArray(body.error.details) && body.error.details.length > 0) {
        return body.error.details
          .map((issue: any) => (issue.msg ?? "Invalid input").replace(/^Value error,\s*/i, ""))
          .join(" ");
      }
      return body.error.message;
    }

    // Support raw FastAPI RequestValidationError format fallback
    if (Array.isArray(body.detail) && body.detail.length > 0) {
      return body.detail
        .map((issue: any) => (issue.msg ?? "Invalid input").replace(/^Value error,\s*/i, ""))
        .join(" ");
    }
  } catch {
    // Non-JSON error body - fall through to the generic message.
  }
  return `The API responded with status ${response.status}.`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new ApiError("The analysis request timed out. Please try again.");
    }
    throw new ApiError(`Cannot reach the ScamSentry API at ${API_URL}. Is the backend running?`);
  }
  if (!response.ok) {
    throw new ApiError(await readErrorMessage(response), response.status);
  }
  return (await response.json()) as T;
}

/** Send a message to the backend for SAFE / SPAM / SCAM analysis. */
export function analyzeMessage(text: string): Promise<PredictResponse> {
  return request<PredictResponse>("/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
}

export function checkHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

/** Scan a URL. */
export function scanUrl(url: string): Promise<PredictResponse> {
  return request<PredictResponse>("/scan-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
}
