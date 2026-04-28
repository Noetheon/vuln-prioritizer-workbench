import { ArrowLeft, Crosshair, ShieldCheck } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { Badge } from "../components/Badges";
import DenseFindingsTable from "../components/DenseFindingsTable";
import EmptyState from "../components/EmptyState";
import KpiStrip from "../components/KpiStrip";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { formatCount, formatDate } from "../lib/format";
import { useTechniqueDetail } from "../hooks/useWorkbenchQueries";

export default function TechniqueDetailPage() {
  const { projectId, techniqueId } = useParams();
  const techniqueQuery = useTechniqueDetail(projectId, techniqueId);

  if (!projectId || !techniqueId) {
    return <EmptyState title="No technique selected">Open a coverage technique from a project.</EmptyState>;
  }

  if (techniqueQuery.isLoading) {
    return <LoadingPanel label="Loading technique" />;
  }

  if (techniqueQuery.error) {
    return <ErrorPanel error={techniqueQuery.error} />;
  }

  const technique = techniqueQuery.data;
  if (!technique) {
    return <ErrorPanel error={new Error("Technique detail not found.")} />;
  }

  const coverage = technique.coverage;

  return (
    <main className="page-grid">
      <section className="content-column">
        <Link className="text-link" to={`/projects/${projectId}/coverage`}>
          <ArrowLeft aria-hidden="true" size={16} />
          Back to coverage
        </Link>

        <section className="detail-hero">
          <div>
            <span>Technique detail</span>
            <h2>{technique.technique_id}</h2>
            <div className="detail-chip-row">
              <Badge tone={coverageTone(coverage?.coverage_level)}>{coverage?.coverage_level ?? "unmapped"}</Badge>
              {technique.revoked ? <Badge tone="critical">revoked</Badge> : null}
              {technique.deprecated ? <Badge tone="high">deprecated</Badge> : null}
            </div>
          </div>
          <div className="detail-rank">
            <span>Findings</span>
            <strong>{technique.findings.length}</strong>
          </div>
        </section>

        <KpiStrip
          items={[
            { label: "Critical", value: coverage?.critical_finding_count ?? 0, tone: "critical" },
            { label: "KEV", value: coverage?.kev_finding_count ?? 0, tone: "critical" },
            { label: "Controls", value: technique.controls.length, tone: technique.controls.length ? "good" : "neutral" },
            { label: "Owner", value: coverage?.owner ?? "Unassigned" }
          ]}
        />

        <section className="panel-section">
          <div className="panel-heading compact">
            <div>
              <span>ATT&CK context</span>
              <h3>{technique.name ?? "Unnamed technique"}</h3>
            </div>
            <Crosshair aria-hidden="true" size={18} />
          </div>
          <dl className="definition-grid">
            <div>
              <dt>Tactics</dt>
              <dd>{technique.tactics.length ? technique.tactics.join(", ") : "N.A."}</dd>
            </div>
            <div>
              <dt>Recommended action</dt>
              <dd>{coverage?.recommended_action ?? "No project coverage gap recorded."}</dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>{coverage?.evidence_refs.length ? coverage.evidence_refs.join(", ") : "N.A."}</dd>
            </div>
          </dl>
        </section>

        <section className="panel-section">
          <div className="panel-heading compact">
            <div>
              <span>{formatCount(technique.findings.length)} findings</span>
              <h3>Mapped vulnerability queue</h3>
            </div>
          </div>
          <DenseFindingsTable
            findings={technique.findings}
            projectId={projectId}
            emptyMessage="No findings are mapped to this technique."
          />
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <div className="rail-title">
            <ShieldCheck aria-hidden="true" size={18} />
            <h2>Detection controls</h2>
          </div>
          <div className="rail-list">
            {technique.controls.map((control) => (
              <div className="rail-row" key={control.id}>
                <span>{control.control_id ?? control.technique_id}</span>
                <strong>{control.name}</strong>
                <small>
                  {control.coverage_level} · {control.owner || "Unassigned"} · {formatDate(control.last_verified_at)}
                </small>
              </div>
            ))}
            {technique.controls.length === 0 ? <p className="muted">No detection controls cover this technique.</p> : null}
          </div>
        </section>
      </aside>
    </main>
  );
}

function coverageTone(level: string | null | undefined): string {
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
