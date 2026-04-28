import { CheckCircle2, Save, ShieldQuestion, Trash2 } from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { Badge } from "../components/Badges";
import EmptyState from "../components/EmptyState";
import KpiStrip from "../components/KpiStrip";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { apiDelete, apiPatch, apiPost } from "../api/client";
import type { Finding, Waiver } from "../api/types";
import { formatCount, formatDate, governanceLabel } from "../lib/format";
import { useProjectFindings, useProjectWaivers } from "../hooks/useWorkbenchQueries";

interface WaiverFormState {
  cve_id: string;
  finding_id: string;
  asset_id: string;
  component_name: string;
  component_version: string;
  service: string;
  owner: string;
  reason: string;
  expires_on: string;
  review_on: string;
  approval_ref: string;
  ticket_url: string;
}

const EMPTY_WAIVERS: Waiver[] = [];

export default function WaiversPage() {
  const { projectId } = useParams();
  const queryClient = useQueryClient();
  const findingFilters = useMemo(() => ({ limit: 100, sort: "operational" }), []);
  const waiversQuery = useProjectWaivers(projectId);
  const findingsQuery = useProjectFindings(projectId, findingFilters);
  const [createDraft, setCreateDraft] = useState<WaiverFormState>(emptyWaiverForm);
  const [editDraft, setEditDraft] = useState<WaiverFormState>(emptyWaiverForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submittingAction, setSubmittingAction] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const waivers = waiversQuery.data?.items ?? EMPTY_WAIVERS;
  const findings = findingsQuery.data?.items ?? [];
  const selectedWaiver = useMemo(
    () => waivers.find((waiver) => waiver.id === editingId) ?? null,
    [editingId, waivers]
  );

  function startEditing(waiver: Waiver) {
    setEditingId(waiver.id);
    setEditDraft(waiverToForm(waiver));
    setSuccess(null);
    setError(null);
  }

  async function createWaiver(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    setSubmittingAction("create");
    setSuccess(null);
    setError(null);
    try {
      const created = await apiPost<Waiver>(`/api/projects/${projectId}/waivers`, waiverPayload(createDraft));
      setCreateDraft(emptyWaiverForm);
      setSuccess(`Waiver created for ${scopeLabel(created)}.`);
      await invalidateWaiverContext(queryClient, projectId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function updateWaiver(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingId || !projectId) {
      return;
    }
    setSubmittingAction(editingId);
    setSuccess(null);
    setError(null);
    try {
      const updated = await apiPatch<Waiver>(`/api/waivers/${editingId}`, waiverPayload(editDraft));
      setEditDraft(waiverToForm(updated));
      setSuccess(`Waiver updated for ${scopeLabel(updated)}.`);
      await invalidateWaiverContext(queryClient, projectId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function deleteWaiver(waiver: Waiver) {
    if (!projectId || !window.confirm(`Delete waiver for ${scopeLabel(waiver)}?`)) {
      return;
    }
    setSubmittingAction(`delete:${waiver.id}`);
    setSuccess(null);
    setError(null);
    try {
      await apiDelete<{ deleted: boolean }>(`/api/waivers/${waiver.id}`);
      if (editingId === waiver.id) {
        setEditingId(null);
      }
      setSuccess(`Waiver deleted for ${scopeLabel(waiver)}.`);
      await invalidateWaiverContext(queryClient, projectId);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  if (!projectId) {
    return <EmptyState title="No project selected">Open a project before managing waivers.</EmptyState>;
  }

  if (waiversQuery.isLoading) {
    return <LoadingPanel label="Loading waivers" />;
  }

  if (waiversQuery.error) {
    return <ErrorPanel error={waiversQuery.error} />;
  }

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Risk acceptance</span>
          <h2>Waiver lifecycle</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Waivers", value: waivers.length },
            { label: "Active", value: waivers.filter((waiver) => waiver.status === "active").length, tone: "good" },
            {
              label: "Review due",
              value: waivers.filter((waiver) => waiver.status === "review_due").length,
              tone: "high"
            },
            {
              label: "Expired",
              value: waivers.filter((waiver) => waiver.status === "expired").length,
              tone: "critical"
            },
            {
              label: "Matched findings",
              value: waivers.reduce((total, waiver) => total + waiver.matched_findings, 0)
            }
          ]}
        />

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Create waiver</span>
              <h3>Document accepted residual risk</h3>
            </div>
            <ShieldQuestion aria-hidden="true" size={18} />
          </div>
          <WaiverForm
            draft={createDraft}
            findings={findings}
            onChange={setCreateDraft}
            onSubmit={createWaiver}
            submitLabel={submittingAction === "create" ? "Creating" : "Create waiver"}
            submitting={submittingAction === "create"}
          />
          {findingsQuery.error ? (
            <p className="status-copy">Finding options could not be loaded; scoped fields can still be entered manually.</p>
          ) : null}
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>{formatCount(waivers.length)} records</span>
              <h3>Current waivers</h3>
            </div>
          </div>
          {success ? (
            <div className="action-banner">
              <CheckCircle2 aria-hidden="true" size={16} />
              <span>{success}</span>
            </div>
          ) : null}
          {error ? <div className="action-banner is-error">{error}</div> : null}
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Current risk waivers</caption>
              <thead>
                <tr>
                  <th scope="col">Scope</th>
                  <th scope="col">Status</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Review</th>
                  <th scope="col">Matches</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {waivers.map((waiver) => (
                  <tr key={waiver.id}>
                    <th scope="row" className="row-header">{scopeLabel(waiver)}</th>
                    <td>
                      <Badge tone={waiverStatusTone(waiver.status)}>{governanceLabel(waiver.status)}</Badge>
                    </td>
                    <td>{waiver.owner}</td>
                    <td>{formatDate(waiver.expires_on)}</td>
                    <td>{formatDate(waiver.review_on)}</td>
                    <td>{waiver.matched_findings}</td>
                    <td>{waiver.reason}</td>
                    <td>
                      <div className="inline-actions">
                        <button
                          className={`icon-text-button ${editingId === waiver.id ? "primary" : ""}`}
                          type="button"
                          onClick={() => startEditing(waiver)}
                          aria-label={`Review waiver for ${scopeLabel(waiver)}`}
                        >
                          <Save aria-hidden="true" size={16} />
                          Review
                        </button>
                        <button
                          className="icon-button"
                          type="button"
                          onClick={() => void deleteWaiver(waiver)}
                          disabled={submittingAction === `delete:${waiver.id}`}
                          aria-label={`Delete waiver for ${scopeLabel(waiver)}`}
                        >
                          <Trash2 aria-hidden="true" size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {waivers.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="table-empty">
                      No persisted waivers yet.
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
            <Save aria-hidden="true" size={18} />
            <h2>Save review</h2>
          </div>
          {selectedWaiver ? (
            <WaiverForm
              compact
              draft={editDraft}
              findings={findings}
              onChange={setEditDraft}
              onSubmit={updateWaiver}
              submitLabel={submittingAction === selectedWaiver.id ? "Saving" : "Save review"}
              submitting={submittingAction === selectedWaiver.id}
            />
          ) : (
            <p className="muted">Select a waiver to update its scope, dates, owner, approval reference, and reason.</p>
          )}
        </section>
      </aside>
    </main>
  );
}

function WaiverForm({
  draft,
  findings,
  onChange,
  onSubmit,
  submitLabel,
  submitting,
  compact = false
}: {
  draft: WaiverFormState;
  findings: Finding[];
  onChange: (next: WaiverFormState) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  submitLabel: string;
  submitting: boolean;
  compact?: boolean;
}) {
  function setField(field: keyof WaiverFormState, value: string) {
    onChange({ ...draft, [field]: value });
  }

  return (
    <form className={`form-grid ${compact ? "is-compact" : ""}`} onSubmit={onSubmit}>
      <label>
        CVE
        <input
          value={draft.cve_id}
          onChange={(event) => setField("cve_id", event.target.value)}
          placeholder="CVE-2024-3094"
        />
      </label>
      <label>
        Finding
        <select value={draft.finding_id} onChange={(event) => setField("finding_id", event.target.value)}>
          <option value="">Any matching finding</option>
          {findings.map((finding) => (
            <option value={finding.id} key={finding.id}>
              {findingLabel(finding)}
            </option>
          ))}
        </select>
      </label>
      <label>
        Asset
        <input value={draft.asset_id} onChange={(event) => setField("asset_id", event.target.value)} />
      </label>
      <label>
        Service
        <input value={draft.service} onChange={(event) => setField("service", event.target.value)} />
      </label>
      <label>
        Component
        <input value={draft.component_name} onChange={(event) => setField("component_name", event.target.value)} />
      </label>
      <label>
        Version
        <input
          value={draft.component_version}
          onChange={(event) => setField("component_version", event.target.value)}
        />
      </label>
      <label>
        Owner
        <input required value={draft.owner} onChange={(event) => setField("owner", event.target.value)} />
      </label>
      <label>
        Expires
        <input
          required
          type="date"
          value={draft.expires_on}
          onChange={(event) => setField("expires_on", event.target.value)}
        />
      </label>
      <label>
        Review
        <input type="date" value={draft.review_on} onChange={(event) => setField("review_on", event.target.value)} />
      </label>
      <label>
        Approval
        <input value={draft.approval_ref} onChange={(event) => setField("approval_ref", event.target.value)} />
      </label>
      <label>
        Ticket
        <input value={draft.ticket_url} onChange={(event) => setField("ticket_url", event.target.value)} />
      </label>
      <label className="full-span">
        Reason
        <textarea required value={draft.reason} onChange={(event) => setField("reason", event.target.value)} />
      </label>
      <p className="field-help full-span">
        At least one scope field is required: CVE, finding, asset, service, component, or version.
      </p>
      <div className="button-row">
        <button className="icon-text-button primary" type="submit" disabled={submitting}>
          <Save aria-hidden="true" size={16} />
          {submitLabel}
        </button>
      </div>
    </form>
  );
}

const emptyWaiverForm: WaiverFormState = {
  cve_id: "",
  finding_id: "",
  asset_id: "",
  component_name: "",
  component_version: "",
  service: "",
  owner: "",
  reason: "",
  expires_on: "",
  review_on: "",
  approval_ref: "",
  ticket_url: ""
};

function waiverToForm(waiver: Waiver): WaiverFormState {
  return {
    cve_id: waiver.cve_id ?? "",
    finding_id: waiver.finding_id ?? "",
    asset_id: waiver.asset_id ?? "",
    component_name: waiver.component_name ?? "",
    component_version: waiver.component_version ?? "",
    service: waiver.service ?? "",
    owner: waiver.owner,
    reason: waiver.reason,
    expires_on: waiver.expires_on,
    review_on: waiver.review_on ?? "",
    approval_ref: waiver.approval_ref ?? "",
    ticket_url: waiver.ticket_url ?? ""
  };
}

function waiverPayload(draft: WaiverFormState) {
  return {
    cve_id: emptyToNull(draft.cve_id),
    finding_id: emptyToNull(draft.finding_id),
    asset_id: emptyToNull(draft.asset_id),
    component_name: emptyToNull(draft.component_name),
    component_version: emptyToNull(draft.component_version),
    service: emptyToNull(draft.service),
    owner: draft.owner.trim(),
    reason: draft.reason.trim(),
    expires_on: draft.expires_on.trim(),
    review_on: emptyToNull(draft.review_on),
    approval_ref: emptyToNull(draft.approval_ref),
    ticket_url: emptyToNull(draft.ticket_url)
  };
}

async function invalidateWaiverContext(queryClient: ReturnType<typeof useQueryClient>, projectId: string) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ["waivers", projectId] }),
    queryClient.invalidateQueries({ queryKey: ["findings", projectId] }),
    queryClient.invalidateQueries({ queryKey: ["dashboard", projectId] }),
    queryClient.invalidateQueries({ queryKey: ["governance", projectId] })
  ]);
}

function scopeLabel(waiver: Waiver): string {
  return [
    waiver.cve_id,
    waiver.asset_id,
    waiver.service,
    waiver.component_name,
    waiver.component_version,
    waiver.finding_id ? `finding ${waiver.finding_id.slice(0, 8)}` : null
  ]
    .filter(Boolean)
    .join(" / ") || "Project scope";
}

function findingLabel(finding: Finding): string {
  return [finding.cve_id, finding.asset || "no asset", finding.component].filter(Boolean).join(" / ");
}

function waiverStatusTone(status: string): string {
  if (status === "active") {
    return "good";
  }
  if (status === "review_due") {
    return "high";
  }
  if (status === "expired") {
    return "critical";
  }
  return "neutral";
}

function emptyToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed || null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed.";
}
