import { useCallback, useSyncExternalStore } from "react";

import {
  getSessionApiToken,
  getSessionApiTokenId,
  requestSessionApiToken,
  setSessionApiToken
} from "../api/client";

const listeners = new Set<() => void>();

function emitTokenChange(): void {
  for (const listener of listeners) {
    listener();
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function tokenSnapshot(): string {
  return getSessionApiToken();
}

function tokenIdSnapshot(): string {
  return getSessionApiTokenId();
}

export function useSessionToken() {
  const token = useSyncExternalStore(subscribe, tokenSnapshot, () => "");
  const tokenId = useSyncExternalStore(subscribe, tokenIdSnapshot, () => "");

  const storeToken = useCallback((nextToken: string, nextTokenId?: string) => {
    setSessionApiToken(nextToken, nextTokenId);
    emitTokenChange();
  }, []);

  const promptForToken = useCallback(() => {
    void requestSessionApiToken().catch(() => undefined);
  }, []);

  const clearToken = useCallback(() => {
    storeToken("");
  }, [storeToken]);

  return {
    token,
    tokenId,
    hasToken: token.length > 0,
    promptForToken,
    clearToken,
    storeToken
  };
}
