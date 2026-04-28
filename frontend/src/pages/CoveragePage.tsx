import { CheckCircle2, FileUp, Layers, ShieldCheck } from "lucide-react";
import { FormEvent, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { Badge } from "../components/Badges";
import EmptyState from "../components/EmptyState";
import KpiStrip from "../components/KpiStrip";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { apiPostForm } from "../api/client";
import type { CoverageGapItem, DetectionControl } from "../api/types";
import { formatCount, formatDate } from "../lib/format";
import { useCoverageGaps, useDetectionControls } from "../hooks/useWorkbenchQueries";

interface DetectionControlImportResponse {
  imported: number;
  items: DetectionControl[];
}

const EMPTY_CONTROLS: DetectionControl[] = [];
const EMPTY_GAPS: CoverageGapItem[] = [];

export default function CoveragePage() {
  const { projectId } = useParams();
  const queryClient = useQueryClient();
  const controlsQuery = useDetectionControls(projectId);
  const gapsQuery = useCoverageGaps(projectId);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const controls = controlsQuery.data?.items ?? EMPTY_CONTROLS;
  const gaps = gapsQuery.data?.items ?? EMPTY_GAPS;
  const sortedGaps = useMemo(() => [...gaps].sort(compareGaps), [gaps]);
  const summary = gapsQuery.data?.summary ?? {};

  async function importControls(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectId || !selectedFile) {
      setError("Select a detection controls CSV or YAML file.");
      return;
    }
    setIsSubmitting(true);
    setSuccess(null);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      const response = await apiPostForm<DetectionControlImportResponse>(
        `/api/projects/${projectId}/detection-controls/import`,
        formData
      );
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
      setSuccess(`${formatCount(response.imported)} detection controls imported.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["detection-controls", projectId] }),
        queryClient.invalidateQueries({ queryKey: ["coverage-gaps", projectId] })
      ]);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!projectId) {
    return <EmptyState title="No project selected">Open a project before importing detection coverage.</EmptyState>;
  }

  if (controlsQuery.isLoading || gapsQuery.isLoading) {
    return <LoadingPanel label="Loading coverage" />;
  }

  if (controlsQuery.error) {
    return <ErrorPanel error={controlsQuery.error} />;
  }

  if (gapsQuery.error) {
    return <ErrorPanel error={gapsQuery.error} />;
  }

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Detection coverage</span>
          <h2>ATT&CK coverage gaps</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Controls", value: controls.length, tone: controls.length ? "good" : "neutral" },
            { label: "Techniques", value: gaps.length },
            { label: "Not covered", value: summary.not_covered ?? 0, tone: "critical" },
            { label: "Unknown", value: summary.unknown ?? 0, tone: "high" },
            { label: "Partial", value: summary.partial ?? 0, tone: "medium" },
            { label: "Covered", value: summary.covered ?? 0, tone: "good" }
          ]}
        />

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Import controls</span>
              <h3>CSV or YAML detection evidence</h3>
            </div>
            <FileUp aria-hidden="true" size={18} />
          </div>
          <form className="filter-panel" onSubmit={importControls}>
            <label>
              Detection controls file
              <input
                ref={fileInputRef}
                required
                type="file"
                accept=".csv,.yml,.yaml,text/csv,text/yaml"
                onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              />
            </label>
            <div className="filter-actions">
              <button className="icon-text-button primary" type="submit" disabled={isSubmitting}>
                <FileUp aria-hidden="true" size={16} />
                {isSubmitting ? "Importing" : "Import"}
              </button>
              <a
                className="icon-text-button"
                href={`/api/projects/${projectId}/attack/coverage-gap-navigator-layer`}
              >
                <Layers aria-hidden="true" size={16} />
                Navigator layer
              </a>
            </div>
          </form>
          {success ? (
            <div className="action-banner">
              <CheckCircle2 aria-hidden="true" size={16} />
              <span>{success}</span>
            </div>
          ) : null}
          {error ? <div className="action-banner is-error">{error}</div> : null}
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Coverage gaps</span>
              <h3>Mapped techniques needing review</h3>
            </div>
            <ShieldCheck aria-hidden="true" size={18} />
          </div>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Detection coverage gaps by ATT&amp;CK technique</caption>
              <thead>
                <tr>
                  <th scope="col">Technique</th>
                  <th scope="col">Name</th>
                  <th scope="col">Coverage</th>
                  <th scope="col">Findings</th>
                  <th scope="col">Critical</th>
                  <th scope="col">KEV</th>
                  <th scope="col">Controls</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {sortedGaps.map((item) => (
                  <tr key={item.technique_id}>
                    <th scope="row" className="row-header">
                      <Link className="table-link" to={`/projects/${projectId}/attack/techniques/${item.technique_id}`}>
                        {item.technique_id}
                      </Link>
                    </th>
                    <td>{item.name || "N.A."}</td>
                    <td>
                      <Badge tone={coverageTone(item.coverage_level)}>{item.coverage_level}</Badge>
                    </td>
                    <td>{item.finding_count}</td>
                    <td>{item.critical_finding_count}</td>
                    <td>{item.kev_finding_count}</td>
                    <td>{item.control_count}</td>
                    <td>{item.owner || "Unassigned"}</td>
                    <td>{item.recommended_action}</td>
                  </tr>
                ))}
                {sortedGaps.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="table-empty">
                      No mapped techniques are available for coverage analysis.
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
            <ShieldCheck aria-hidden="true" size={18} />
            <h2>Imported controls</h2>
          </div>
          <div className="rail-list">
            {controls.slice(0, 8).map((control) => (
              <div className="rail-row" key={control.id}>
                <span>{control.technique_id}</span>
                <strong>{control.name}</strong>
                <small>
                  {control.coverage_level} · {control.owner || "Unassigned"}
                </small>
              </div>
            ))}
            {controls.length === 0 ? <p className="muted">No detection controls imported.</p> : null}
          </div>
        </section>

        <section className="rail-section">
          <h2>Control evidence</h2>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Detection control evidence</caption>
              <thead>
                <tr>
                  <th scope="col">Control</th>
                  <th scope="col">Coverage</th>
                  <th scope="col">Verified</th>
                </tr>
              </thead>
              <tbody>
                {controls.map((control) => (
                  <tr key={control.id}>
                    <th scope="row" className="row-header">{control.control_id || control.name}</th>
                    <td>{control.coverage_level}</td>
                    <td>{formatDate(control.last_verified_at)}</td>
                  </tr>
                ))}
                {controls.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="table-empty">
                      No controls.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      </aside>
    </main>
  );
}

function compareGaps(first: { coverage_level: string; finding_count: number; technique_id: string }, second: typeof first) {
  const coverageOrder: Record<string, number> = {
    not_covered: 0,
    unknown: 1,
    partial: 2,
    covered: 3,
    not_applicable: 4
  };
  return (
    (coverageOrder[first.coverage_level] ?? 5) - (coverageOrder[second.coverage_level] ?? 5) ||
    second.finding_count - first.finding_count ||
    first.technique_id.localeCompare(second.technique_id)
  );
}

function coverageTone(level: string): string {
  if (level === "covered") {
    return "good";
  }
  if (level === "partial") {
    return "medium";
  }
  if (level === "not_covered") {
    return "critical";
  }
  if (level === "unknown") {
    return "high";
  }
  return "neutral";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed.";
}
