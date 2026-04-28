import { DatabaseZap } from "lucide-react";

import type { ProviderStatusResponse } from "../api/types";

interface ProviderChipsProps {
  status?: ProviderStatusResponse;
  compact?: boolean;
}

export default function ProviderChips({ status, compact = false }: ProviderChipsProps) {
  if (!status) {
    return (
      <div className="provider-chip-row" aria-label="Provider status loading">
        <span className="provider-chip provider-chip-muted">Providers loading</span>
      </div>
    );
  }

  return (
    <div className={`provider-chip-row ${compact ? "is-compact" : ""}`} aria-label="Provider status">
      <span className={`provider-chip provider-chip-${status.snapshot.missing ? "missing" : "ready"}`}>
        <DatabaseZap aria-hidden="true" size={14} />
        {status.status}
      </span>
      {status.sources.map((source) => (
        <span
          className={`provider-chip ${
            source.available ? (source.stale ? "provider-chip-stale" : "provider-chip-ready") : "provider-chip-missing"
          }`}
          key={source.name}
          title={source.detail ?? undefined}
        >
          {source.name.toUpperCase()}
          {compact ? null : <small>{source.value ?? "Missing"}</small>}
        </span>
      ))}
    </div>
  );
}
