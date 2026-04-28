import { ArrowLeft, Bug, FileJson, Fingerprint, Network } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { Badge, PriorityBadge } from "../components/Badges";
import KpiStrip from "../components/KpiStrip";
import ProviderChips from "../components/ProviderChips";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { ApiError } from "../api/client";
import {
  compactHash,
  formatPercent,
  formatScore,
  governanceLabel
} from "../lib/format";
import {
  useFinding,
  useFindingAttackContext,
  useFindingExplain,
  useProviderStatus
} from "../hooks/useWorkbenchQueries";

export default function FindingDetailPage() {
  const { projectId, findingId } = useParams();
  const findingQuery = useFinding(findingId);
  const attackQuery = useFindingAttackContext(findingId);
  const explainQuery = useFindingExplain(findingId);
  const providerQuery = useProviderStatus();

  if (findingQuery.isLoading) {
    return <LoadingPanel label="Loading finding" />;
  }

  if (findingQuery.error) {
    return <ErrorPanel error={findingQuery.error} />;
  }

  const finding = findingQuery.data;
  if (!finding) {
    return <ErrorPanel error={new Error("Finding not found.")} />;
  }

  const attackContext = attackQuery.data;
  const attackError = attackQuery.error instanceof ApiError && attackQuery.error.status === 404 ? null : attackQuery.error;
  const explain = explainQuery.data;

  return (
    <main className="page-grid">
      <section className="content-column">
        <Link className="text-link" to={`/projects/${projectId ?? finding.project_id}/findings`}>
          <ArrowLeft aria-hidden="true" size={16} />
          Back to findings
        </Link>

        <section className="detail-hero">
          <div>
            <span>Finding detail</span>
            <h2>{finding.cve_id}</h2>
            <div className="detail-chip-row">
              <PriorityBadge priority={finding.priority} />
              {finding.in_kev ? <Badge tone="critical">KEV</Badge> : null}
              {finding.attack_mapped ? <Badge tone="good">ATT&CK mapped</Badge> : null}
              <Badge>{finding.status}</Badge>
            </div>
          </div>
          <div className="detail-rank">
            <span>Operational rank</span>
            <strong>{finding.operational_rank}</strong>
          </div>
        </section>

        <KpiStrip
          items={[
            { label: "EPSS", value: formatPercent(finding.epss), tone: "high" },
            { label: "CVSS", value: formatScore(finding.cvss_base_score), tone: "critical" },
            { label: "Threat rank", value: finding.threat_context_rank ?? "N.A.", tone: "neutral" },
            { label: "Waiver", value: governanceLabel(finding.waiver_status ?? (finding.waived ? "active" : null)) }
          ]}
        />

        <section className="detail-grid">
          <article className="panel-section">
            <div className="panel-heading compact">
              <div>
                <span>Rationale</span>
                <h3>Why this priority</h3>
              </div>
              <Bug aria-hidden="true" size={18} />
            </div>
            <p className="body-copy">{finding.rationale ?? "No rationale captured."}</p>
          </article>
          <article className="panel-section">
            <div className="panel-heading compact">
              <div>
                <span>Action</span>
                <h3>Recommended next step</h3>
              </div>
              <Fingerprint aria-hidden="true" size={18} />
            </div>
            <p className="body-copy">{finding.recommended_action ?? "N.A."}</p>
          </article>
        </section>

        <section className="panel-section">
          <div className="panel-heading compact">
            <div>
              <span>Asset context</span>
              <h3>Where this finding applies</h3>
            </div>
          </div>
          <dl className="definition-grid">
            <div>
              <dt>Component</dt>
              <dd>{finding.component ?? "N.A."}</dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{finding.component_version ?? "N.A."}</dd>
            </div>
            <div>
              <dt>Asset</dt>
              <dd>{finding.asset ?? "N.A."}</dd>
            </div>
            <div>
              <dt>Service</dt>
              <dd>{finding.service ?? "N.A."}</dd>
            </div>
            <div>
              <dt>Owner</dt>
              <dd>{finding.owner ?? "N.A."}</dd>
            </div>
            <div>
              <dt>Governance</dt>
              <dd>{governanceSummary(finding)}</dd>
            </div>
          </dl>
        </section>

        <section className="panel-section">
          <div className="panel-heading compact">
            <div>
              <span>Raw evidence</span>
              <h3>Finding JSON</h3>
            </div>
            <FileJson aria-hidden="true" size={18} />
          </div>
          <details className="json-details">
            <summary>Show JSON payload</summary>
            <pre>{JSON.stringify(finding.finding ?? {}, null, 2)}</pre>
          </details>
        </section>

        <section className="panel-section">
          <div className="panel-heading compact">
            <div>
              <span>Explain API</span>
              <h3>Decision trace</h3>
            </div>
            <FileJson aria-hidden="true" size={18} />
          </div>
          {explainQuery.error ? <p className="body-copy">Explain payload is not available.</p> : null}
          {!explainQuery.error ? (
            <>
              <dl className="definition-grid">
                <div>
                  <dt>Priority</dt>
                  <dd>{explain?.priority ?? finding.priority}</dd>
                </div>
                <div>
                  <dt>Rationale</dt>
                  <dd>{explain?.rationale ?? finding.rationale ?? "N.A."}</dd>
                </div>
                <div>
                  <dt>Action</dt>
                  <dd>{explain?.recommended_action ?? finding.recommended_action ?? "N.A."}</dd>
                </div>
              </dl>
              <details className="json-details">
                <summary>Show explanation payload</summary>
                <pre>{JSON.stringify(explain?.explanation ?? {}, null, 2)}</pre>
              </details>
            </>
          ) : null}
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <h2>Providers</h2>
          <ProviderChips status={providerQuery.data} />
        </section>

        <section className="rail-section">
          <div className="rail-title">
            <Network aria-hidden="true" size={18} />
            <h2>ATT&CK context</h2>
          </div>
          {attackError ? <ErrorPanel error={attackError} /> : null}
          {!attackError && attackContext?.mapped ? (
            <div className="rail-list">
              <div className="rail-row">
                <span>Source</span>
                <strong>{attackContext.source}</strong>
                <small>{attackContext.attack_version ?? "version N.A."}</small>
              </div>
              <div className="rail-row">
                <span>Review</span>
                <strong>{attackContext.review_status}</strong>
                <small>{attackContext.attack_relevance}</small>
              </div>
              <div className="rail-row">
                <span>Mapping hash</span>
                <strong>{compactHash(attackContext.source_hash)}</strong>
                <small>{attackContext.domain ?? "enterprise-attack"}</small>
              </div>
              {attackContext.techniques.map((technique, index) => (
                <div className="rail-row" key={`${techniqueId(technique)}-${index}`}>
                  <span>{techniqueId(technique)}</span>
                  <strong>
                    <Link className="table-link" to={`/projects/${projectId ?? finding.project_id}/attack/techniques/${techniqueId(technique)}`}>
                      {techniqueName(technique)}
                    </Link>
                  </strong>
                  <small>{techniqueTactics(technique)}</small>
                </div>
              ))}
            </div>
          ) : null}
          {!attackError && !attackContext?.mapped ? <p className="muted">No approved ATT&CK mapping is stored.</p> : null}
        </section>

        <section className="rail-section">
          <h2>VEX and waiver</h2>
          <div className="rail-list">
            <div className="rail-row">
              <span>VEX</span>
              <strong>{finding.suppressed_by_vex ? "suppressed" : finding.under_investigation ? "review" : "N.A."}</strong>
              <small>{Object.keys(finding.vex_statuses).join(", ") || "no statuses"}</small>
            </div>
            <div className="rail-row">
              <span>Waiver</span>
              <strong>{governanceLabel(finding.waiver_status ?? (finding.waived ? "active" : null))}</strong>
              <small>{finding.waiver_owner ?? finding.waiver_scope ?? "no owner"}</small>
            </div>
          </div>
        </section>
      </aside>
    </main>
  );
}

function governanceSummary(finding: {
  waiver_status?: string | null;
  waived: boolean;
  waiver_owner?: string | null;
  waiver_expires_on?: string | null;
  suppressed_by_vex: boolean;
  under_investigation: boolean;
}): string {
  if (finding.waiver_status || finding.waived) {
    return `waiver ${governanceLabel(finding.waiver_status ?? "active")} · ${finding.waiver_owner ?? "unowned"} · expires ${
      finding.waiver_expires_on ?? "N.A."
    }`;
  }
  if (finding.suppressed_by_vex) {
    return "VEX suppressed";
  }
  if (finding.under_investigation) {
    return "VEX review";
  }
  return "N.A.";
}

function techniqueId(technique: Record<string, unknown>): string {
  const value = technique.attack_object_id ?? technique.technique_id ?? technique.id;
  return typeof value === "string" ? value : "N.A.";
}

function techniqueName(technique: Record<string, unknown>): string {
  const value = technique.name;
  return typeof value === "string" ? value : "Unnamed";
}

function techniqueTactics(technique: Record<string, unknown>): string {
  const value = technique.tactics;
  return Array.isArray(value) ? value.filter((item) => typeof item === "string").join(", ") : "N.A.";
}
