import { Download, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { apiPost } from "../api/client";
import type { EvidenceBundle, ReportArtifact } from "../api/types";
import { Badge } from "../components/Badges";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { compactHash, formatDateTime } from "../lib/format";
import { useRunArtifacts, useWorkbenchBootstrap } from "../hooks/useWorkbenchQueries";

export default function RunArtifactsPage() {
  const { projectId, runId } = useParams();
  const artifactsQuery = useRunArtifacts(runId);
  const bootstrapQuery = useWorkbenchBootstrap();
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState("");

  async function createReport(format: string) {
    if (!runId) {
      return;
    }
    setMessage("");
    setError("");
    setSubmitting(`report-${format}`);
    try {
      await apiPost<ReportArtifact>(`/api/analysis-runs/${runId}/reports`, { format });
      setMessage(`${format.toUpperCase()} report generated.`);
      await artifactsQuery.refetch();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Report generation failed.");
    } finally {
      setSubmitting("");
    }
  }

  async function createEvidenceBundle() {
    if (!runId) {
      return;
    }
    setMessage("");
    setError("");
    setSubmitting("bundle");
    try {
      await apiPost<EvidenceBundle>(`/api/analysis-runs/${runId}/evidence-bundle`);
      setMessage("Evidence bundle generated.");
      await artifactsQuery.refetch();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Evidence bundle generation failed.");
    } finally {
      setSubmitting("");
    }
  }

  if (artifactsQuery.isLoading) {
    return <LoadingPanel label="Loading run artifacts" />;
  }

  if (artifactsQuery.error) {
    return <ErrorPanel error={artifactsQuery.error} />;
  }

  const payload = artifactsQuery.data;
  const formats = bootstrapQuery.data?.supported_report_formats ?? ["html", "markdown", "json", "csv", "sarif"];

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Artifacts</span>
          <h2>Reports and evidence</h2>
        </div>
        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Analysis run</span>
              <h3>{payload?.run.input_filename ?? payload?.run.id}</h3>
            </div>
            <Link className="icon-text-button" to={`/projects/${projectId}/dashboard`}>
              Dashboard
            </Link>
          </div>
          <div className="form-grid is-compact">
            {formats.map((format) => (
              <button
                className="icon-text-button"
                type="button"
                key={format}
                disabled={Boolean(submitting)}
                onClick={() => void createReport(format)}
              >
                {submitting === `report-${format}` ? "Generating..." : `Create ${format}`}
              </button>
            ))}
            <button
              className="icon-text-button primary"
              type="button"
              disabled={Boolean(submitting)}
              onClick={() => void createEvidenceBundle()}
            >
              <ShieldCheck aria-hidden="true" size={16} />
              {submitting === "bundle" ? "Generating..." : "Create evidence bundle"}
            </button>
            {payload?.run.summary.attack_enabled ? (
              <a className="icon-text-button" href={`/api/analysis-runs/${runId}/attack/navigator-layer`}>
                <Download aria-hidden="true" size={16} />
                ATT&CK navigator
              </a>
            ) : null}
          </div>
          {message ? <div className="action-banner">{message}</div> : null}
          {error ? <div className="action-banner is-error">{error}</div> : null}
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>{payload?.items.length ?? 0} artifacts</span>
              <h3>Generated outputs</h3>
            </div>
          </div>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Generated run artifacts</caption>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Format</th>
                  <th scope="col">Created</th>
                  <th scope="col">SHA-256</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(payload?.items ?? []).map((item) => (
                  <tr key={item.id}>
                    <th scope="row" className="row-header">
                      <Badge tone={item.type === "evidence_bundle" ? "good" : "neutral"}>{item.kind}</Badge>
                    </th>
                    <td>{item.format ?? "N.A."}</td>
                    <td>{formatDateTime(item.created_at)}</td>
                    <td>{compactHash(item.sha256)}</td>
                    <td>
                      <div className="inline-actions">
                        <a className="icon-text-button" href={item.download_url}>
                          <Download aria-hidden="true" size={16} />
                          Download
                        </a>
                        {item.verify_url ? (
                          <Link className="icon-text-button" to={`/evidence-bundles/${item.id}/verify`}>
                            Verify
                          </Link>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {payload?.items.length === 0 ? <div className="table-empty">No generated artifacts yet.</div> : null}
          </div>
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <h2>Run summary</h2>
          <div className="rail-list">
            <div className="rail-row">
              <span>Status</span>
              <strong>{payload?.run.status}</strong>
              <small>{formatDateTime(payload?.run.finished_at ?? payload?.run.started_at)}</small>
            </div>
            <div className="rail-row">
              <span>Findings</span>
              <strong>{payload?.run.summary.findings_count ?? 0}</strong>
              <small>{payload?.run.summary.kev_hits ?? 0} KEV hits</small>
            </div>
            <div className="rail-row">
              <span>ATT&CK</span>
              <strong>{payload?.run.summary.attack_enabled ? "enabled" : "off"}</strong>
              <small>{payload?.run.summary.attack_mapped_cves ?? 0} mapped CVEs</small>
            </div>
          </div>
        </section>
      </aside>
    </main>
  );
}
