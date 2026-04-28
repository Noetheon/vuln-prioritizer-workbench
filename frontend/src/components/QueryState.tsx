import { KeyRound, Loader2 } from "lucide-react";

import { ApiError } from "../api/client";
import { useSessionToken } from "../hooks/useSessionToken";

interface LoadingPanelProps {
  label?: string;
  as?: "div" | "main";
}

export function LoadingPanel({ label = "Loading", as: Component = "div" }: LoadingPanelProps) {
  return (
    <Component className="state-panel" role="status" aria-live="polite">
      <Loader2 aria-hidden="true" className="spin" size={22} />
      <span>{label}</span>
    </Component>
  );
}

export function ErrorPanel({ error, as: Component = "div" }: { error: unknown; as?: "div" | "main" }) {
  const { promptForToken } = useSessionToken();
  const message = error instanceof Error ? error.message : "Request failed.";
  const status = error instanceof ApiError ? error.status : undefined;

  return (
    <Component className="state-panel state-panel-error" role="alert" aria-live="assertive">
      <strong>{status ? `Request failed (${status})` : "Request failed"}</strong>
      <span>{message}</span>
      {status === 401 || status === 403 ? (
        <button className="icon-text-button" type="button" onClick={promptForToken}>
          <KeyRound aria-hidden="true" size={16} />
          Set token
        </button>
      ) : null}
    </Component>
  );
}
