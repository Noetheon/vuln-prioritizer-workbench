import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  apiGet,
  apiPost,
  apiPostForm,
  getSessionApiToken,
  getSessionApiTokenId,
  requestSessionApiToken,
  setSessionApiToken,
  setTokenRequestHandler
} from "./client";

const store = new Map<string, string>();

describe("api client", () => {
  beforeEach(() => {
    store.clear();
    Object.defineProperty(globalThis, "sessionStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => store.get(key) ?? null,
        setItem: (key: string, value: string) => store.set(key, value),
        removeItem: (key: string) => store.delete(key)
      }
    });
  });

  afterEach(() => {
    setTokenRequestHandler(null);
    vi.restoreAllMocks();
  });

  it("sends the session token on API requests", async () => {
    setSessionApiToken("vpr_test");
    const fetchMock = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet<{ ok: boolean }>("/api/example");

    const init = requestInit(fetchMock);
    const headers = init.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer vpr_test");
    expect(headers.get("Accept")).toBe("application/json");
  });

  it("serializes JSON mutations", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ id: "1" }));
    vi.stubGlobal("fetch", fetchMock);

    await apiPost<{ id: string }>("/api/projects", { name: "demo" });

    const init = requestInit(fetchMock);
    const headers = init.headers as Headers;
    expect(init.method).toBe("POST");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(init.body).toBe('{"name":"demo"}');
  });

  it("does not force a content type for multipart form uploads", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ id: "run" }));
    vi.stubGlobal("fetch", fetchMock);

    await apiPostForm<{ id: string }>("/api/projects/1/imports", new FormData());

    const init = requestInit(fetchMock);
    const headers = init.headers as Headers;
    expect(headers.get("Content-Type")).toBeNull();
  });

  it("trims and clears session tokens", () => {
    setSessionApiToken("  vpr_trimmed  ", "token-1");
    expect(getSessionApiToken()).toBe("vpr_trimmed");
    expect(getSessionApiTokenId()).toBe("token-1");
    setSessionApiToken("");
    expect(getSessionApiToken()).toBe("");
    expect(getSessionApiTokenId()).toBe("");
  });

  it("retries a forbidden request once after collecting a session token", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(
        { detail: "API token required.", error: { message: "API token required." } },
        { status: 401 }
      ))
      .mockResolvedValueOnce(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    const tokenRequest = vi.fn(async () => {
      setSessionApiToken("vpr_retry");
      return "vpr_retry";
    });
    setTokenRequestHandler(tokenRequest);

    await expect(apiPost<{ ok: boolean }>("/api/projects", { name: "demo" })).resolves.toEqual({
      ok: true
    });

    expect(tokenRequest).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const retryInit = (fetchMock.mock.calls as Array<[RequestInfo | URL, RequestInit]>)[1][1];
    expect((retryInit.headers as Headers).get("Authorization")).toBe("Bearer vpr_retry");
  });

  it("deduplicates concurrent session token prompts", async () => {
    let resolveToken!: (token: string) => void;
    const tokenRequest = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          resolveToken = resolve;
        })
    );
    setTokenRequestHandler(tokenRequest);

    const firstRequest = requestSessionApiToken();
    const secondRequest = requestSessionApiToken();
    resolveToken?.("vpr_concurrent");

    await expect(firstRequest).resolves.toBe("vpr_concurrent");
    await expect(secondRequest).resolves.toBe("vpr_concurrent");
    expect(tokenRequest).toHaveBeenCalledTimes(1);
  });
});

function jsonResponse(payload: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init
  });
}

function requestInit(fetchMock: ReturnType<typeof vi.fn>): RequestInit {
  const calls = fetchMock.mock.calls as Array<[RequestInfo | URL, RequestInit]>;
  return calls[0][1];
}
