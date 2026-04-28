import { Download, FileArchive, ShieldCheck } from "lucide-react";
import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { Badge } from "../components/Badges";
import KpiStrip from "../components/KpiStrip";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { compactHash, formatCount, formatDateTime } from "../lib/format";
import { useGeneratedArtifacts, useProjectRuns } from "../hooks/useWorkbenchQueries";

export default function ArtifactsPage() {
  const { projectId } = useParams();
  const runsQuery = useProjectRuns(projectId);
  const artifactsQuery = useGeneratedArtifacts(200);

  const projectArtifacts = useMemo(
    () => (artifactsQuery.data?.items ?? []).filter((item) => item.project_id === projectId),
    [artifactsQuery.data?.items, projectId]
  );
  const runs = runsQuery.data?.items ?? [];
  const reportCount = projectArtifacts.filter((item) => item.type === "report").length;
  const evidenceCount = projectArtifacts.filter((item) => item.type === "evidence_bundle").length;

  if (runsQuery.isLoading || artifactsQuery.isLoading) {
    return <LoadingPanel label="Loading generated artifacts" />;
  }

  if (runsQuery.error) {
    return <ErrorPanel error={runsQuery.error} />;
  }

  if (artifactsQuery.error) {
    return <ErrorPanel error={artifactsQuery.error} />;
  }

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Artifacts</span>
          <h2>Run history and generated outputs</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Runs", value: runs.length },
            { label: "Artifacts", value: projectArtifacts.length },
            { label: "Reports", value: reportCount },
            { label: "Evidence bundles", value: evidenceCount, tone: evidenceCount ? "good" : "neutral" }
          ]}
        />

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>{formatCount(runs.length)} runs</span>
              <h3>Analysis run history</h3>
            </div>
          </div>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Analysis run history</caption>
              <thead>
                <tr>
                  <th scope="col">Input</th>
                  <th scope="col">Status</th>
                  <th scope="col">Started</th>
                  <th scope="col">Findings</th>
                  <th scope="col">ATT&CK</th>
                  <th scope="col">Artifacts</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.id}>
                    <th scope="row" className="row-header">{run.input_filename ?? run.input_type}</th>
                    <td>
                      <Badge tone={run.status === "failed" ? "critical" : "good"}>{run.status}</Badge>
                    </td>
                    <td>{formatDateTime(run.started_at)}</td>
                    <td>{run.summary.findings_count}</td>
                    <td>{run.summary.attack_enabled ? `${run.summary.attack_mapped_cves} mapped` : "Off"}</td>
                    <td>
                      <Link className="icon-text-button" to={`/projects/${projectId}/runs/${run.id}/artifacts`}>
                        <FileArchive aria-hidden="true" size={16} />
                        Open artifacts
                      </Link>
                    </td>
                  </tr>
                ))}
                {runs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="table-empty">
                      No analysis runs yet.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>{formatCount(projectArtifacts.length)} artifacts</span>
              <h3>Generated report and evidence files</h3>
            </div>
          </div>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Generated Workbench artifacts</caption>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Format</th>
                  <th scope="col">Created</th>
                  <th scope="col">Run</th>
                  <th scope="col">SHA-256</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {projectArtifacts.map((item) => (
                  <tr key={item.id}>
                    <th scope="row" className="row-header">
                      <Badge tone={item.type === "evidence_bundle" ? "good" : "neutral"}>{item.kind}</Badge>
                    </th>
                    <td>{item.format ?? "N.A."}</td>
                    <td>{formatDateTime(item.created_at)}</td>
                    <td>{compactHash(item.analysis_run_id)}</td>
                    <td>{compactHash(item.sha256)}</td>
                    <td>
                      <div className="inline-actions">
                        <a className="icon-text-button" href={item.download_url}>
                          <Download aria-hidden="true" size={16} />
                          Download
                        </a>
                        {item.verify_url ? (
                          <Link className="icon-text-button" to={`/evidence-bundles/${item.id}/verify`}>
                            <ShieldCheck aria-hidden="true" size={16} />
                            Verify
                          </Link>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
                {projectArtifacts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="table-empty">
                      No generated artifacts yet.
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
          <h2>Artifact workflow</h2>
          <div className="rail-list">
            <div className="rail-row">
              <span>Generate</span>
              <strong>run-level</strong>
              <small>Open a run to create HTML, Markdown, JSON, CSV, SARIF, and evidence bundles.</small>
            </div>
            <div className="rail-row">
              <span>Verify</span>
              <strong>evidence</strong>
              <small>Evidence bundles keep hash manifests and browser-accessible integrity checks.</small>
            </div>
          </div>
        </section>
      </aside>
    </main>
  );
}
