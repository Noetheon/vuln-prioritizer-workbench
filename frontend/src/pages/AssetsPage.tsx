import { CheckCircle2, Database, Save, SquarePen } from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { Badge } from "../components/Badges";
import EmptyState from "../components/EmptyState";
import KpiStrip from "../components/KpiStrip";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { apiPatch } from "../api/client";
import type { Asset } from "../api/types";
import { formatCount } from "../lib/format";
import { useProjectAssets } from "../hooks/useWorkbenchQueries";

interface AssetFormState {
  asset_id: string;
  target_ref: string;
  owner: string;
  business_service: string;
  environment: string;
  exposure: string;
  criticality: string;
}

const EMPTY_ASSETS: Asset[] = [];

export default function AssetsPage() {
  const { projectId } = useParams();
  const queryClient = useQueryClient();
  const assetsQuery = useProjectAssets(projectId);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<AssetFormState>(emptyAssetForm);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const assets = assetsQuery.data?.items ?? EMPTY_ASSETS;
  const selectedAsset = useMemo(
    () => assets.find((asset) => asset.id === editingId) ?? null,
    [assets, editingId]
  );
  const totalFindings = useMemo(
    () => assets.reduce((total, asset) => total + asset.finding_count, 0),
    [assets]
  );

  function startEditing(asset: Asset) {
    setEditingId(asset.id);
    setDraft(assetToForm(asset));
    setSuccess(null);
    setError(null);
  }

  async function submitAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingId) {
      return;
    }
    setIsSubmitting(true);
    setSuccess(null);
    setError(null);
    try {
      const updated = await apiPatch<Asset>(`/api/assets/${editingId}`, assetPayload(draft));
      setDraft(assetToForm(updated));
      setSuccess(`${updated.asset_id} updated.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["assets", projectId] }),
        queryClient.invalidateQueries({ queryKey: ["findings", projectId] }),
        queryClient.invalidateQueries({ queryKey: ["dashboard", projectId] }),
        queryClient.invalidateQueries({ queryKey: ["governance", projectId] })
      ]);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!projectId) {
    return <EmptyState title="No project selected">Open a project before editing asset context.</EmptyState>;
  }

  if (assetsQuery.isLoading) {
    return <LoadingPanel label="Loading assets" />;
  }

  if (assetsQuery.error) {
    return <ErrorPanel error={assetsQuery.error} />;
  }

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Assets</span>
          <h2>Asset context editor</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Assets", value: assets.length },
            { label: "Linked findings", value: totalFindings, tone: totalFindings ? "high" : "neutral" },
            { label: "Owned", value: assets.filter((asset) => asset.owner).length, tone: "good" },
            {
              label: "Critical",
              value: assets.filter((asset) => asset.criticality?.toLowerCase() === "critical").length,
              tone: "critical"
            }
          ]}
        />

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>{formatCount(assets.length)} records</span>
              <h3>Imported asset inventory</h3>
            </div>
            <Database aria-hidden="true" size={18} />
          </div>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Imported asset inventory</caption>
              <thead>
                <tr>
                  <th scope="col">Asset</th>
                  <th scope="col">Target</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Service</th>
                  <th scope="col">Environment</th>
                  <th scope="col">Exposure</th>
                  <th scope="col">Criticality</th>
                  <th scope="col">Findings</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.id}>
                    <th scope="row" className="row-header">{asset.asset_id}</th>
                    <td>{asset.target_ref || "N.A."}</td>
                    <td>{asset.owner || "Unassigned"}</td>
                    <td>{asset.business_service || "Unmapped"}</td>
                    <td>{asset.environment || "N.A."}</td>
                    <td>{asset.exposure || "N.A."}</td>
                    <td>
                      <Badge tone={criticalityTone(asset.criticality)}>{asset.criticality || "N.A."}</Badge>
                    </td>
                    <td>{asset.finding_count}</td>
                    <td>
                      <button
                        className={`icon-text-button ${editingId === asset.id ? "primary" : ""}`}
                        type="button"
                        onClick={() => startEditing(asset)}
                        aria-label={`Edit asset ${asset.asset_id}`}
                      >
                        <SquarePen aria-hidden="true" size={16} />
                        Edit
                      </button>
                    </td>
                  </tr>
                ))}
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="table-empty">
                      No assets captured yet. Import asset context with a Workbench run.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <div className="rail-title">
            <SquarePen aria-hidden="true" size={18} />
            <h2>Edit asset</h2>
          </div>
          {selectedAsset ? (
            <form className="form-grid is-compact" onSubmit={submitAsset}>
              <label>
                Asset
                <input
                  required
                  value={draft.asset_id}
                  onChange={(event) => setDraft({ ...draft, asset_id: event.target.value })}
                />
              </label>
              <label>
                Target
                <input
                  value={draft.target_ref}
                  onChange={(event) => setDraft({ ...draft, target_ref: event.target.value })}
                />
              </label>
              <label>
                Owner
                <input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} />
              </label>
              <label>
                Service
                <input
                  value={draft.business_service}
                  onChange={(event) => setDraft({ ...draft, business_service: event.target.value })}
                />
              </label>
              <label>
                Environment
                <input
                  value={draft.environment}
                  onChange={(event) => setDraft({ ...draft, environment: event.target.value })}
                />
              </label>
              <label>
                Exposure
                <input
                  value={draft.exposure}
                  onChange={(event) => setDraft({ ...draft, exposure: event.target.value })}
                />
              </label>
              <label>
                Criticality
                <input
                  value={draft.criticality}
                  onChange={(event) => setDraft({ ...draft, criticality: event.target.value })}
                />
              </label>
              <div className="button-row">
                <button className="icon-text-button primary" type="submit" disabled={isSubmitting}>
                  <Save aria-hidden="true" size={16} />
                  {isSubmitting ? "Saving" : "Save"}
                </button>
              </div>
              {success ? (
                <div className="action-banner">
                  <CheckCircle2 aria-hidden="true" size={16} />
                  <span>{success}</span>
                </div>
              ) : null}
              {error ? <div className="action-banner is-error">{error}</div> : null}
            </form>
          ) : (
            <p className="muted">Select an asset row to update ownership, service, exposure, and criticality.</p>
          )}
        </section>
      </aside>
    </main>
  );
}

const emptyAssetForm: AssetFormState = {
  asset_id: "",
  target_ref: "",
  owner: "",
  business_service: "",
  environment: "",
  exposure: "",
  criticality: ""
};

function assetToForm(asset: Asset): AssetFormState {
  return {
    asset_id: asset.asset_id,
    target_ref: asset.target_ref ?? "",
    owner: asset.owner ?? "",
    business_service: asset.business_service ?? "",
    environment: asset.environment ?? "",
    exposure: asset.exposure ?? "",
    criticality: asset.criticality ?? ""
  };
}

function assetPayload(draft: AssetFormState) {
  return {
    asset_id: draft.asset_id.trim(),
    target_ref: emptyToNull(draft.target_ref),
    owner: emptyToNull(draft.owner),
    business_service: emptyToNull(draft.business_service),
    environment: emptyToNull(draft.environment),
    exposure: emptyToNull(draft.exposure),
    criticality: emptyToNull(draft.criticality)
  };
}

function emptyToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed || null;
}

function criticalityTone(value: string | undefined | null): string {
  const normalized = (value ?? "").toLowerCase();
  if (normalized === "critical") {
    return "critical";
  }
  if (normalized === "high") {
    return "high";
  }
  if (normalized === "medium") {
    return "medium";
  }
  if (normalized === "low") {
    return "good";
  }
  return "neutral";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed.";
}
