import { Gavel, ShieldAlert, UserCheck } from "lucide-react";
import type { ReactNode } from "react";
import { useParams } from "react-router-dom";

import KpiStrip from "../components/KpiStrip";
import ProviderChips from "../components/ProviderChips";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import type { GovernanceRollupItem } from "../api/types";
import { formatCount, governanceLabel, topEntries } from "../lib/format";
import { useGovernanceRollups, useProviderStatus } from "../hooks/useWorkbenchQueries";

export default function GovernancePage() {
  const { projectId } = useParams();
  const governanceQuery = useGovernanceRollups(projectId, 20);
  const providerQuery = useProviderStatus();

  if (governanceQuery.isLoading) {
    return <LoadingPanel label="Loading governance rollups" />;
  }

  if (governanceQuery.error) {
    return <ErrorPanel error={governanceQuery.error} />;
  }

  const governance = governanceQuery.data;

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Governance</span>
          <h2>Ownership, waivers, and VEX pressure</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Total findings", value: governance?.total_findings ?? 0 },
            { label: "Waived", value: governance?.waiver_summary.waived_count ?? 0, tone: "good" },
            { label: "Review due", value: governance?.waiver_summary.review_due_count ?? 0, tone: "high" },
            { label: "Expired", value: governance?.waiver_summary.expired_count ?? 0, tone: "critical" },
            { label: "VEX suppressed", value: governance?.vex_summary.suppressed_findings ?? 0, tone: "good" },
            { label: "VEX review", value: governance?.vex_summary.under_investigation_findings ?? 0, tone: "medium" }
          ]}
        />

        <section className="governance-grid">
          <RollupTable title="Remediation owners" icon={<UserCheck aria-hidden="true" size={18} />} items={governance?.owners ?? []} />
          <RollupTable title="Service pressure" icon={<ShieldAlert aria-hidden="true" size={18} />} items={governance?.services ?? []} />
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <h2>Providers</h2>
          <ProviderChips status={providerQuery.data} />
        </section>
        <section className="rail-section">
          <div className="rail-title">
            <Gavel aria-hidden="true" size={18} />
            <h2>Waiver owners</h2>
          </div>
          <div className="rail-list">
            {topEntries(governance?.waiver_summary.waiver_owner_counts ?? {}).map(([owner, count]) => (
              <div className="rail-row" key={owner}>
                <span>{owner}</span>
                <strong>{count}</strong>
                <small>active ownership</small>
              </div>
            ))}
            {topEntries(governance?.waiver_summary.waiver_owner_counts ?? {}).length === 0 ? (
              <p className="muted">No waiver ownership captured.</p>
            ) : null}
          </div>
        </section>
        <section className="rail-section">
          <h2>VEX statuses</h2>
          <div className="rail-list">
            {topEntries(governance?.vex_summary.status_counts ?? {}).map(([status, count]) => (
              <div className="rail-row" key={status}>
                <span>{governanceLabel(status)}</span>
                <strong>{count}</strong>
                <small>status count</small>
              </div>
            ))}
            {topEntries(governance?.vex_summary.status_counts ?? {}).length === 0 ? (
              <p className="muted">No VEX statuses captured.</p>
            ) : null}
          </div>
        </section>
      </aside>
    </main>
  );
}

function RollupTable({
  title,
  icon,
  items
}: {
  title: string;
  icon: ReactNode;
  items: GovernanceRollupItem[];
}) {
  return (
    <section className="panel-section">
      <div className="panel-heading compact">
        <div>
          <span>{title}</span>
          <h3>{formatCount(items.length)} groups</h3>
        </div>
        {icon}
      </div>
      <div className="dense-table-wrap">
        <table className="dense-table">
          <caption className="sr-only">{title} governance rollups</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Actionable</th>
              <th scope="col">Critical</th>
              <th scope="col">High</th>
              <th scope="col">KEV</th>
              <th scope="col">Waived</th>
              <th scope="col">Top CVEs</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.dimension}-${item.label}`}>
                <th scope="row" className="row-header">{item.label}</th>
                <td>{item.actionable_count}</td>
                <td>{item.critical_count}</td>
                <td>{item.high_count}</td>
                <td>{item.kev_count}</td>
                <td>{item.waived_count}</td>
                <td>{item.top_cves.join(", ") || "N.A."}</td>
              </tr>
            ))}
            {items.length === 0 ? (
              <tr>
                <td colSpan={7}>No governance rollups.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
