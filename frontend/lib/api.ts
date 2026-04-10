import { ScanResults, StartScanResponse } from "@/lib/types";

const REQUEST_TIMEOUT_MS = 30_000;
const SLOW_START_THRESHOLD_MS = 5_000;
const LOCAL_API_URL = "http://localhost:8000";
const PRODUCTION_PROXY_PATH = "/api";

function getEnvironmentApiUrl(): string {
  return process.env.NEXT_PUBLIC_API_URL ?? LOCAL_API_URL;
}

export function getApiBaseUrl(): string {
  const configured = getEnvironmentApiUrl().replace(/\/$/, "");

  if (typeof window === "undefined") {
    return configured.endsWith("/api") ? configured : `${configured}/api`;
  }

  const hostname = window.location.hostname;
  const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
  if (!isLocalhost) {
    return PRODUCTION_PROXY_PATH;
  }

  return `${LOCAL_API_URL}/api`;
}

class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function getFriendlyNetworkError(error: unknown): ApiError {
  if (error instanceof DOMException && error.name === "AbortError") {
    return new ApiError(
      "The security engine is taking longer than expected. If the free backend is waking up, give it another moment and try again.",
      408,
      "timeout"
    );
  }

  return new ApiError(
    "DomainVitals could not reach the security engine. This can happen when the free backend is waking up or when CORS is not configured yet.",
    503,
    "network"
  );
}

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit = {}, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    throw getFriendlyNetworkError(error);
  } finally {
    clearTimeout(timeout);
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (response.ok) {
    return (await response.json()) as T;
  }

  let detail = `Request failed with status ${response.status}`;
  try {
    const payload = (await response.json()) as { detail?: string };
    if (payload.detail) {
      detail = payload.detail;
    }
  } catch {
    detail = response.statusText || detail;
  }
  throw new ApiError(detail, response.status);
}

export interface StartScanResult {
  data: StartScanResponse;
  durationMs: number;
  slowStartDetected: boolean;
}

export function validateDomain(domain: string): string | null {
  const normalized = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  const pattern = /^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;

  if (!normalized) {
    return "Enter a domain to scan.";
  }
  if (!pattern.test(normalized)) {
    return "Enter a valid public domain like yourbusiness.com.";
  }
  if (normalized === "localhost") {
    return "Localhost cannot be scanned.";
  }
  return null;
}

export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].replace(/\.$/, "");
}

export async function startScan(domain: string): Promise<StartScanResult> {
  const startedAt = Date.now();
  const response = await fetchWithTimeout(`${getApiBaseUrl()}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ domain: normalizeDomain(domain) })
  });

  return {
    data: await parseResponse<StartScanResponse>(response),
    durationMs: Date.now() - startedAt,
    slowStartDetected: Date.now() - startedAt >= SLOW_START_THRESHOLD_MS
  };
}

export async function getScanResults(scanId: string): Promise<ScanResults> {
  const response = await fetchWithTimeout(`${getApiBaseUrl()}/results/${scanId}`, {
    cache: "no-store"
  });
  return parseResponse<ScanResults>(response);
}

export async function getReportPdf(scanId: string): Promise<void> {
  const response = await fetchWithTimeout(`${getApiBaseUrl()}/report/${scanId}/pdf`, {
    cache: "no-store"
  }, 60_000);

  if (!response.ok) {
    let message = "Unable to download PDF report.";
    try {
      const payload = (await response.json()) as { detail?: string };
      if (payload.detail) {
        message = payload.detail;
      }
    } catch {
      message = response.statusText || message;
    }
    throw new ApiError(message, response.status);
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = `domainvitals-report-${scanId}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

export { ApiError, REQUEST_TIMEOUT_MS, SLOW_START_THRESHOLD_MS };
