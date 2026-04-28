import { Activity, AlertTriangle, Crosshair, History, ShieldCheck, Upload } from "lucide-react";
import type { ReactNode } from "react";
import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import DenseFindingsTable from "../components/DenseFindingsTable";
import KpiStrip, { type KpiItem } from "../components/KpiStrip";
import ProviderChips from "../components/ProviderChips";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import type { GovernanceRollupItem } from "../api/types";
import {
  formatCount,
  formatDateTime,
  governanceLabel
} from "../lib/format";
import {
  useGovernanceRollups,
  useProjectDashboard
} from "../hooks/useWorkbenchQueries";

export default function DashboardPage() {
  const { projectId } = useParams();
  const dashboardQuery = useProjectDashboard(projectId);
  const governanceQuery = useGovernanceRollups(projectId, 8);

  if (dashboardQuery.isLoading) {
    return <LoadingPanel label="Loading triage queue" />;
  }

  if (dashboardQuery.error) {
    return <ErrorPanel error={dashboardQuery.error} />;
  }

  const dashboard = dashboardQuery.data;
  const counts = dashboard?.counts ?? {};
  const kpis = dashboardKpis(counts);
  const topFindings = dashboard?.top_findings ?? [];

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Operational command</span>
          <h2>Prioritized work queue</h2>
        </div>
        <div className="inline-actions">
          <Link className="icon-text-button primary" to={`/projects/${projectId}/imports/new`}>
            <Upload aria-hidden="true" size={16} />
            Import findings
          </Link>
        </div>
        <KpiStrip items={kpis} />

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Top findings</span>
              <h3>Rule-based triage order</h3>
            </div>
            <Link className="icon-text-button" to={`/projects/${projectId}/findings`}>
              View all
            </Link>
          </div>
          <DenseFindingsTable
            findings={topFindings}
            projectId={projectId ?? ""}
            maxRows={12}
            density="summary"
          />
        </section>

        <section className="rollup-grid">
          <RollupPreview
            title="Owner pressure"
            icon={<ShieldCheck aria-hidden="true" size={18} />}
            items={governanceQuery.data?.owners ?? []}
          />
          <RollupPreview
            title="Service pressure"
            icon={<Activity aria-hidden="true" size={18} />}
            items={governanceQuery.data?.services ?? []}
          />
        </section>
      </section>

      <aside className="intelligence-rail" aria-label="Intelligence rail">
        <section className="rail-section">
          <div className="rail-title">
            <Crosshair aria-hidden="true" size={18} />
            <h2>Provider intelligence</h2>
          </div>
          <ProviderChips status={dashboard?.provider_status} />
          {dashboard?.provider_status.warnings.map((warning) => (
            <p className="rail-warning" key={warning}>
              {warning}
            </p>
          ))}
        </section>

        <section className="rail-section">
          <div className="rail-title">
            <AlertTriangle aria-hidden="true" size={18} />
            <h2>ATT&CK pressure</h2>
          </div>
          <div className="rail-list">
            {(dashboard?.top_techniques ?? []).map((technique) => (
              <Link
                className="rail-row rail-link"
                key={technique.technique_id}
                to={`/projects/${projectId}/attack/techniques/${encodeURIComponent(technique.technique_id)}`}
              >
                <span>{technique.technique_id}</span>
                <strong>{technique.count}</strong>
                <small>{technique.name}</small>
              </Link>
            ))}
            {dashboard?.top_techniques.length === 0 ? <p className="muted">No mapped techniques.</p> : null}
          </div>
        </section>

        <section className="rail-section">
          <div className="rail-title">
            <History aria-hidden="true" size={18} />
            <h2>Recent imports</h2>
          </div>
          <div className="rail-list">
            {(dashboard?.recent_runs ?? []).slice(0, 6).map((run) => (
              <Link className="rail-row rail-link" key={run.id} to={`/projects/${projectId}/runs/${run.id}/artifacts`}>
                <span>{run.input_type}</span>
                <strong>{run.status}</strong>
                <small>{formatDateTime(run.started_at)}</small>
              </Link>
            ))}
            {dashboard?.recent_runs.length === 0 ? <p className="muted">No import runs.</p> : null}
          </div>
        </section>
      </aside>
    </main>
  );
}

function dashboardKpis(counts: Record<string, number>): KpiItem[] {
  return [
    { label: "Critical", value: counts.Critical ?? 0, tone: "critical" },
    { label: "High", value: counts.High ?? 0, tone: "high" },
    { label: "Medium", value: counts.Medium ?? 0, tone: "medium" },
    { label: "Low", value: counts.Low ?? 0, tone: "good" },
    { label: "KEV", value: counts.KEV ?? 0, tone: "critical" },
    { label: "Open", value: counts.Open ?? 0, tone: "neutral" },
    { label: "VEX suppressed", value: counts["VEX suppressed"] ?? 0, tone: "good" },
    {
      label: "Waiver review",
      value: counts["Waiver review due"] ?? 0,
      tone: counts["Waiver review due"] ? "high" : "good"
    }
  ];
}

function RollupPreview({
  title,
  icon,
  items
}: {
  title: string;
  icon: ReactNode;
  items: GovernanceRollupItem[];
}) {
  const topItems = useMemo(() => items.slice(0, 5), [items]);
  return (
    <section className="panel-section">
      <div className="panel-heading compact">
        <div>
          <span>{title}</span>
          <h3>{formatCount(items.length)} groups</h3>
        </div>
        {icon}
      </div>
      <div className="rollup-list">
        {topItems.map((item) => (
          <div className="rollup-row" key={`${item.dimension}-${item.label}`}>
            <span>{item.label}</span>
            <strong>{item.actionable_count}</strong>
            <small>
              {item.highest_priority} · {item.kev_count} KEV · {governanceLabel(item.status_counts.open ? "open" : null)}
            </small>
          </div>
        ))}
        {topItems.length === 0 ? <p className="muted">No rollup context.</p> : null}
      </div>
    </section>
  );
}
