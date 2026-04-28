import { Filter, RotateCcw } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";

import DenseFindingsTable from "../components/DenseFindingsTable";
import KpiStrip from "../components/KpiStrip";
import ProviderChips from "../components/ProviderChips";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { formatCount } from "../lib/format";
import { useProjectFindings, useProviderStatus } from "../hooks/useWorkbenchQueries";

const defaultFilters = {
  q: "",
  priority: "",
  status: "",
  kev: "",
  owner: "",
  service: "",
  min_epss: "",
  min_cvss: "",
  sort: "operational",
  offset: "0"
};

export default function FindingsPage() {
  const { projectId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const searchKey = searchParams.toString();
  const [draft, setDraft] = useState(() => currentFilters(searchParams));
  const filters = useMemo(() => currentFilters(new URLSearchParams(searchKey)), [searchKey]);
  const findingsQuery = useProjectFindings(projectId, {
    ...filters,
    limit: 100,
    offset: Number(filters.offset) || 0
  });
  const providerQuery = useProviderStatus();

  useEffect(() => {
    setDraft(filters);
  }, [filters]);

  function submitFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSearchParams(cleanParams({ ...draft, offset: "0" }));
  }

  function resetFilters() {
    setDraft(defaultFilters);
    setSearchParams(cleanParams(defaultFilters));
  }

  if (findingsQuery.isLoading) {
    return <LoadingPanel label="Loading findings" />;
  }

  if (findingsQuery.error) {
    return <ErrorPanel error={findingsQuery.error} />;
  }

  const response = findingsQuery.data;
  const findings = response?.items ?? [];
  const offset = response?.offset ?? 0;
  const limit = response?.limit ?? 100;
  const total = response?.total ?? 0;
  const nextOffset = offset + limit < total ? offset + limit : null;
  const previousOffset = Math.max(0, offset - limit);
  const activeFilters = Object.entries(filters).filter(
    ([key, value]) => value && key !== "sort" && key !== "offset"
  );

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Findings</span>
          <h2>Dense vulnerability queue</h2>
        </div>
        <KpiStrip
          items={[
            { label: "Results", value: total },
            { label: "Page", value: `${offset + (total ? 1 : 0)}-${Math.min(offset + findings.length, total)}` },
            { label: "Critical", value: findings.filter((finding) => finding.priority === "Critical").length, tone: "critical" },
            { label: "KEV", value: findings.filter((finding) => finding.in_kev).length, tone: "critical" }
          ]}
        />

        <form className="filter-panel" onSubmit={submitFilters}>
          <label>
            Search
            <input
              value={draft.q}
              onChange={(event) => setDraft({ ...draft, q: event.target.value })}
              placeholder="CVE, component, owner"
            />
          </label>
          <label>
            Priority
            <select value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: event.target.value })}>
              <option value="">Any</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
            </select>
          </label>
          <label>
            Status
            <select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
              <option value="">Any</option>
              <option value="open">Open</option>
              <option value="accepted">Accepted</option>
              <option value="suppressed">Suppressed</option>
              <option value="fixed">Fixed</option>
            </select>
          </label>
          <label>
            KEV
            <select value={draft.kev} onChange={(event) => setDraft({ ...draft, kev: event.target.value })}>
              <option value="">Any</option>
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </label>
          <label>
            Owner
            <input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} />
          </label>
          <label>
            Service
            <input value={draft.service} onChange={(event) => setDraft({ ...draft, service: event.target.value })} />
          </label>
          <label>
            Min EPSS
            <input
              type="number"
              min="0"
              max="1"
              step="0.01"
              value={draft.min_epss}
              onChange={(event) => setDraft({ ...draft, min_epss: event.target.value })}
            />
          </label>
          <label>
            Min CVSS
            <input
              type="number"
              min="0"
              max="10"
              step="0.1"
              value={draft.min_cvss}
              onChange={(event) => setDraft({ ...draft, min_cvss: event.target.value })}
            />
          </label>
          <label>
            Sort
            <select value={draft.sort} onChange={(event) => setDraft({ ...draft, sort: event.target.value })}>
              <option value="operational">Operational</option>
              <option value="priority">Priority</option>
              <option value="epss">EPSS</option>
              <option value="cvss">CVSS</option>
              <option value="cve">CVE</option>
              <option value="last_seen">Last seen</option>
            </select>
          </label>
          <div className="filter-actions">
            <button className="icon-text-button primary" type="submit">
              <Filter aria-hidden="true" size={16} />
              Apply
            </button>
            <button className="icon-button" type="button" onClick={resetFilters} aria-label="Reset filters">
              <RotateCcw aria-hidden="true" size={16} />
            </button>
          </div>
        </form>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Showing {formatCount(findings.length)} rows</span>
              <h3>{formatCount(total)} matching findings</h3>
            </div>
            <div className="pager">
              <button
                className="icon-text-button"
                type="button"
                disabled={offset === 0}
                onClick={() => setSearchParams(cleanParams({ ...filters, offset: String(previousOffset) }))}
              >
                Previous
              </button>
              <button
                className="icon-text-button"
                type="button"
                disabled={nextOffset === null}
                onClick={() => setSearchParams(cleanParams({ ...filters, offset: String(nextOffset ?? offset) }))}
              >
                Next
              </button>
            </div>
          </div>
          <DenseFindingsTable findings={findings} projectId={projectId ?? ""} />
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <div className="rail-title">
            <Filter aria-hidden="true" size={18} />
            <h2>Active filters</h2>
          </div>
          <div className="filter-chip-list">
            {activeFilters.map(([key, value]) => (
              <span className="filter-chip" key={key}>
                {key}: {value}
              </span>
            ))}
            {activeFilters.length === 0 ? <p className="muted">No filters applied.</p> : null}
          </div>
        </section>
        <section className="rail-section">
          <h2>Providers</h2>
          <ProviderChips status={providerQuery.data} />
        </section>
      </aside>
    </main>
  );
}

function currentFilters(searchParams: URLSearchParams) {
  return {
    q: searchParams.get("q") ?? "",
    priority: searchParams.get("priority") ?? "",
    status: searchParams.get("status") ?? "",
    kev: searchParams.get("kev") ?? "",
    owner: searchParams.get("owner") ?? "",
    service: searchParams.get("service") ?? "",
    min_epss: searchParams.get("min_epss") ?? "",
    min_cvss: searchParams.get("min_cvss") ?? "",
    sort: searchParams.get("sort") ?? "operational",
    offset: searchParams.get("offset") ?? "0"
  };
}

function cleanParams(values: typeof defaultFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (!value || (key === "sort" && value === "operational") || (key === "offset" && value === "0")) {
      continue;
    }
    params.set(key, value);
  }
  return params;
}
