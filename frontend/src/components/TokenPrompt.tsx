import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { KeyRound, X } from "lucide-react";

import { setTokenRequestHandler } from "../api/client";
import { useSessionToken } from "../hooks/useSessionToken";

interface PendingTokenRequest {
  resolve: (token: string) => void;
  reject: (error: Error) => void;
}

export default function TokenPrompt() {
  const { hasToken, storeToken } = useSessionToken();
  const [pendingRequest, setPendingRequest] = useState<PendingTokenRequest | null>(null);
  const [tokenDraft, setTokenDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLElement | null>(null);
  const tokenInputRef = useRef<HTMLInputElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  const resetDialog = useCallback(() => {
    setPendingRequest(null);
    setTokenDraft("");
    setError(null);
  }, []);

  const closeDialog = useCallback(() => {
    pendingRequest?.reject(new Error("API token entry cancelled."));
    resetDialog();
  }, [pendingRequest, resetDialog]);

  const trapDialogFocus = useCallback((event: KeyboardEvent) => {
    const focusable = dialogRef.current
      ? Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(
            'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'
          )
        )
      : [];
    if (focusable.length === 0) {
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }, []);

  useEffect(
    () =>
      setTokenRequestHandler(
        () =>
          new Promise<string>((resolve, reject) => {
            setTokenDraft("");
            setError(null);
            setPendingRequest({ resolve, reject });
          })
      ),
    []
  );

  useEffect(() => {
    if (!pendingRequest) {
      return undefined;
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        closeDialog();
        return;
      }
      if (event.key === "Tab") {
        trapDialogFocus(event);
      }
    }
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.addEventListener("keydown", handleKeyDown);
    tokenInputRef.current?.focus();
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previousFocusRef.current?.focus();
      previousFocusRef.current = null;
    };
  }, [closeDialog, pendingRequest, trapDialogFocus]);

  if (!pendingRequest) {
    return null;
  }

  function submitToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = tokenDraft.trim();
    if (!trimmed) {
      setError("Enter an API token.");
      return;
    }
    storeToken(trimmed);
    pendingRequest?.resolve(trimmed);
    resetDialog();
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <section
        ref={dialogRef}
        aria-describedby={error ? "token-dialog-description token-dialog-error" : "token-dialog-description"}
        aria-labelledby="token-dialog-title"
        aria-modal="true"
        className="token-dialog"
        role="dialog"
      >
        <div className="panel-heading">
          <div>
            <span>API token</span>
            <h3 id="token-dialog-title">{hasToken ? "Replace session token" : "Set session token"}</h3>
          </div>
          <button className="icon-button" type="button" onClick={closeDialog} aria-label="Close API token dialog">
            <X aria-hidden="true" size={16} />
          </button>
        </div>
        <p id="token-dialog-description" className="muted">
          Enter a Workbench API token for this browser session.
        </p>
        <form className="form-grid is-compact" onSubmit={submitToken}>
          <label className="full-span">
            Token value
            <input
              ref={tokenInputRef}
              type="password"
              value={tokenDraft}
              onChange={(event) => setTokenDraft(event.target.value)}
              placeholder="vpr_..."
            />
          </label>
          {error ? (
            <p className="field-error full-span" id="token-dialog-error" role="alert">
              {error}
            </p>
          ) : null}
          <div className="button-row full-span">
            <button className="icon-text-button" type="button" onClick={closeDialog}>
              Cancel
            </button>
            <button className="icon-text-button primary" type="submit">
              <KeyRound aria-hidden="true" size={16} />
              Save token
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
