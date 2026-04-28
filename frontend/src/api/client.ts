import type { ApiErrorDetails } from "./types";

const SESSION_TOKEN_KEY = "vpr.workbench.apiToken";
const SESSION_TOKEN_ID_KEY = "vpr.workbench.apiTokenId";

type TokenRequestHandler = () => Promise<string>;

let tokenRequestHandler: TokenRequestHandler | null = null;
let pendingTokenRequest: Promise<string> | null = null;

export function setTokenRequestHandler(handler: TokenRequestHandler | null): () => void {
  tokenRequestHandler = handler;
  return () => {
    if (tokenRequestHandler === handler) {
      tokenRequestHandler = null;
    }
  };
}

export function requestSessionApiToken(): Promise<string> {
  if (!tokenRequestHandler) {
    return Promise.reject(new Error("API token entry is not available."));
  }
  pendingTokenRequest ??= tokenRequestHandler().finally(() => {
    pendingTokenRequest = null;
  });
  return pendingTokenRequest;
}

export function getSessionApiToken(): string {
  return sessionStorage.getItem(SESSION_TOKEN_KEY) ?? "";
}

export function getSessionApiTokenId(): string {
  return sessionStorage.getItem(SESSION_TOKEN_ID_KEY) ?? "";
}

export function setSessionApiToken(token: string, tokenId?: string): void {
  const trimmed = token.trim();
  if (trimmed) {
    sessionStorage.setItem(SESSION_TOKEN_KEY, trimmed);
    if (tokenId) {
      sessionStorage.setItem(SESSION_TOKEN_ID_KEY, tokenId);
    } else {
      sessionStorage.removeItem(SESSION_TOKEN_ID_KEY);
    }
  } else {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    sessionStorage.removeItem(SESSION_TOKEN_ID_KEY);
  }
}

export class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor({ status, message, details }: ApiErrorDetails) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  return apiRequest<T>(path, { method: "GET" });
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return apiRequest<T>(path, jsonInit("POST", body));
}

export async function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  return apiRequest<T>(path, jsonInit("PATCH", body));
}

export async function apiDelete<T>(path: string): Promise<T> {
  return apiRequest<T>(path, { method: "DELETE" });
}

export async function apiPostForm<T>(path: string, formData: FormData): Promise<T> {
  return apiRequest<T>(path, { method: "POST", body: formData });
}

async function apiRequest<T>(path: string, init: RequestInit): Promise<T> {
  let response = await fetchWithSessionToken(path, init);

  if (isAuthChallenge(response.status) && tokenRequestHandler) {
    try {
      await requestSessionApiToken();
      response = await fetchWithSessionToken(path, init);
    } catch {
      // Preserve the original authorization error when token entry is cancelled.
    }
  }

  if (!response.ok) {
    throw await apiErrorFromResponse(response);
  }

  return (await response.json()) as T;
}

function isAuthChallenge(status: number): boolean {
  return status === 401 || status === 403;
}

async function fetchWithSessionToken(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = getSessionApiToken();
  headers.set("Accept", "application/json");
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(path, {
    ...init,
    headers
  });
  return response;
}

async function apiErrorFromResponse(response: Response): Promise<ApiError> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return new ApiError({
    status: response.status,
    message: errorMessage(payload, response.statusText),
    details: payload
  });
}

function jsonInit(method: string, body?: unknown): RequestInit {
  const headers = new Headers();
  headers.set("Content-Type", "application/json");
  return {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  };
}

function errorMessage(payload: unknown, fallback: string): string {
  if (payload && typeof payload === "object") {
    const detail = "detail" in payload ? (payload as { detail?: unknown }).detail : undefined;
    if (typeof detail === "string") {
      return detail;
    }
    const error = "error" in payload ? (payload as { error?: unknown }).error : undefined;
    if (error && typeof error === "object" && "message" in error) {
      const message = (error as { message?: unknown }).message;
      if (typeof message === "string") {
        return message;
      }
    }
  }
  return fallback || "API request failed.";
}
