import { CheckCircle2, ClipboardCopy, FileJson, Github, KeyRound, RefreshCw, Trash2 } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { Badge } from "../components/Badges";
import EmptyState from "../components/EmptyState";
import KpiStrip from "../components/KpiStrip";
import ProviderChips from "../components/ProviderChips";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { apiDelete, apiPost } from "../api/client";
import type {
  ApiTokenCreateResponse,
  ApiTokenMetadata,
  GitHubIssueExportItem,
  GitHubIssueExportRequest,
  GitHubIssueExportResponse,
  GitHubIssuePreviewItem,
  GitHubIssuePreviewRequest,
  GitHubIssuePreviewResponse,
  ProjectConfigSnapshot,
  ProviderUpdateJob
} from "../api/types";
import { compactHash, formatCount, formatDateTime } from "../lib/format";
import { useSessionToken } from "../hooks/useSessionToken";
import {
  useApiTokens,
  useProjectConfig,
  useProviderStatus,
  useProviderUpdateJobs,
  useWorkbenchBootstrap
} from "../hooks/useWorkbenchQueries";

type ProviderSourceName = "nvd" | "epss" | "kev";

const providerSources: ProviderSourceName[] = ["nvd", "epss", "kev"];
const defaultProjectConfig = {
  version: 1,
  defaults: {
    locked_provider_data: true
  },
  commands: {
    analyze: {
      format: "json",
      sort_by: "operational"
    }
  }
} satisfies Record<string, unknown>;

export default function SettingsPage() {
  const { projectId } = useParams();
  const queryClient = useQueryClient();
  const { clearToken, storeToken, tokenId } = useSessionToken();
  const bootstrapQuery = useWorkbenchBootstrap();
  const providerQuery = useProviderStatus();
  const jobsQuery = useProviderUpdateJobs();
  const tokensQuery = useApiTokens();
  const configQuery = useProjectConfig(projectId);
  const [sources, setSources] = useState<Record<ProviderSourceName, boolean>>({
    nvd: true,
    epss: true,
    kev: true
  });
  const [maxCves, setMaxCves] = useState("");
  const [cveIds, setCveIds] = useState("");
  const [cacheOnly, setCacheOnly] = useState(true);
  const [tokenName, setTokenName] = useState("");
  const [newToken, setNewToken] = useState<ApiTokenCreateResponse | null>(null);
  const [configDraft, setConfigDraft] = useState("");
  const [githubLimit, setGithubLimit] = useState("10");
  const [githubPriority, setGithubPriority] = useState("Critical");
  const [githubLabelPrefix, setGithubLabelPrefix] = useState("vuln-prioritizer");
  const [githubMilestone, setGithubMilestone] = useState("");
  const [githubRepository, setGithubRepository] = useState("");
  const [githubTokenEnv, setGithubTokenEnv] = useState("GITHUB_TOKEN");
  const [githubPreview, setGithubPreview] = useState<GitHubIssuePreviewResponse | null>(null);
  const [githubExport, setGithubExport] = useState<GitHubIssueExportResponse | null>(null);
  const [submittingAction, setSubmittingAction] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedSources = useMemo(
    () => providerSources.filter((source) => sources[source]),
    [sources]
  );
  const providerStatus = providerQuery.data;
  const jobs = jobsQuery.data?.items ?? [];
  const tokens = tokensQuery.data?.items ?? [];
  const projectConfig = configQuery.data?.item ?? null;
  const configDraftSource = useMemo(
    () => JSON.stringify(projectConfig?.config ?? defaultProjectConfig, null, 2),
    [projectConfig]
  );

  useEffect(() => {
    setConfigDraft(configDraftSource);
  }, [configDraftSource]);

  async function createProviderJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selectedSources.length === 0) {
      setError("Select at least one provider source.");
      return;
    }
    const parsedMaxCves = maxCves.trim() ? Number(maxCves) : undefined;
    if (parsedMaxCves !== undefined && (!Number.isInteger(parsedMaxCves) || parsedMaxCves < 1 || parsedMaxCves > 500)) {
      setError("Max CVEs must be between 1 and 500.");
      return;
    }
    setSubmittingAction("provider-job");
    setSuccess(null);
    setError(null);
    try {
      const job = await apiPost<ProviderUpdateJob>("/api/providers/update-jobs", {
        sources: selectedSources,
        cve_ids: cveIds.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean),
        max_cves: parsedMaxCves,
        cache_only: cacheOnly
      });
      setSuccess(`Provider update job ${job.status}.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["providers", "status"] }),
        queryClient.invalidateQueries({ queryKey: ["providers", "update-jobs"] }),
        queryClient.invalidateQueries({ queryKey: ["workbench", "bootstrap"] })
      ]);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function createToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmittingAction("token-create");
    setSuccess(null);
    setError(null);
    setNewToken(null);
    try {
      const response = await apiPost<ApiTokenCreateResponse>("/api/tokens", { name: tokenName });
      setNewToken(response);
      setTokenName("");
      setSuccess(`API token ${response.name} created.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["tokens"] }),
        queryClient.invalidateQueries({ queryKey: ["workbench", "bootstrap"] })
      ]);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function revokeToken(token: ApiTokenMetadata) {
    if (!window.confirm(`Revoke API token ${token.name}?`)) {
      return;
    }
    setSubmittingAction(`token:${token.id}`);
    setSuccess(null);
    setError(null);
    try {
      await apiDelete<{ revoked: boolean }>(`/api/tokens/${token.id}`);
      if (token.id === tokenId) {
        clearToken();
      }
      if (newToken?.id === token.id) {
        setNewToken(null);
      }
      setSuccess(`API token ${token.name} revoked.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["tokens"] }),
        queryClient.invalidateQueries({ queryKey: ["workbench", "bootstrap"] })
      ]);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function copyNewToken() {
    if (!newToken) {
      return;
    }
    if (!navigator.clipboard?.writeText) {
      setSuccess(null);
      setError("Clipboard is not available in this browser.");
      return;
    }
    try {
      await navigator.clipboard.writeText(newToken.token);
      setError(null);
      setSuccess(`API token ${newToken.name} copied.`);
    } catch (caught) {
      setSuccess(null);
      setError(`API token could not be copied. ${errorMessage(caught)}`);
    }
  }

  function useNewTokenNow() {
    if (!newToken) {
      return;
    }
    storeToken(newToken.token, newToken.id);
    setSuccess(`API token ${newToken.name} stored for this browser session.`);
  }

  async function saveProjectConfig(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    let parsedConfig: unknown;
    try {
      parsedConfig = JSON.parse(configDraft);
    } catch {
      setSuccess(null);
      setError("Project config must be valid JSON.");
      return;
    }
    if (!parsedConfig || typeof parsedConfig !== "object" || Array.isArray(parsedConfig)) {
      setSuccess(null);
      setError("Project config must be a JSON object.");
      return;
    }
    setSubmittingAction("config-save");
    setSuccess(null);
    setError(null);
    try {
      const snapshot = await apiPost<ProjectConfigSnapshot>(
        `/api/projects/${projectId}/settings/config`,
        { config: parsedConfig }
      );
      setSuccess(`Project config snapshot ${compactHash(snapshot.id)} saved.`);
      await queryClient.invalidateQueries({ queryKey: ["project-config", projectId] });
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function previewGithubIssues(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    setSubmittingAction("github-preview");
    setSuccess(null);
    setError(null);
    setGithubExport(null);
    try {
      const response = await apiPost<GitHubIssuePreviewResponse>(
        `/api/projects/${projectId}/github/issues/preview`,
        githubPreviewPayload()
      );
      setGithubPreview(response);
      setSuccess(`${formatCount(response.items.length)} GitHub issue previews generated.`);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  async function exportGithubIssues(dryRun: boolean) {
    if (!projectId) {
      return;
    }
    if (!githubRepository.trim()) {
      setSuccess(null);
      setError("Enter a GitHub repository in owner/name format.");
      return;
    }
    if (!dryRun && !window.confirm("Create GitHub issues from the current Workbench findings?")) {
      return;
    }
    setSubmittingAction(dryRun ? "github-dry-run" : "github-export");
    setSuccess(null);
    setError(null);
    try {
      const payload: GitHubIssueExportRequest = {
        ...githubPreviewPayload(),
        repository: githubRepository.trim(),
        token_env: githubTokenEnv.trim() || "GITHUB_TOKEN",
        dry_run: dryRun
      };
      const response = await apiPost<GitHubIssueExportResponse>(
        `/api/projects/${projectId}/github/issues/export`,
        payload
      );
      setGithubExport(response);
      setGithubPreview(null);
      setSuccess(
        dryRun
          ? `${formatCount(response.items.length)} GitHub issue exports prepared.`
          : `${formatCount(response.created_count)} GitHub issues created.`
      );
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmittingAction(null);
    }
  }

  function githubPreviewPayload(): GitHubIssuePreviewRequest {
    const parsedLimit = Number(githubLimit);
    return {
      limit: Number.isInteger(parsedLimit) && parsedLimit >= 1 && parsedLimit <= 100 ? parsedLimit : 20,
      priority: githubPriority || undefined,
      label_prefix: githubLabelPrefix.trim() || "vuln-prioritizer",
      milestone: githubMilestone.trim() || undefined
    };
  }

  if (!projectId) {
    return <EmptyState title="No project selected">Open a project before managing Workbench settings.</EmptyState>;
  }

  if (
    bootstrapQuery.isLoading ||
    providerQuery.isLoading ||
    jobsQuery.isLoading ||
    tokensQuery.isLoading ||
    configQuery.isLoading
  ) {
    return <LoadingPanel label="Loading settings" />;
  }

  if (bootstrapQuery.error) {
    return <ErrorPanel error={bootstrapQuery.error} />;
  }

  if (providerQuery.error) {
    return <ErrorPanel error={providerQuery.error} />;
  }

  if (jobsQuery.error) {
    return <ErrorPanel error={jobsQuery.error} />;
  }

  if (tokensQuery.error) {
    return <ErrorPanel error={tokensQuery.error} />;
  }

  if (configQuery.error) {
    return <ErrorPanel error={configQuery.error} />;
  }

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Settings</span>
          <h2>Providers, integrations, and API tokens</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Provider status", value: providerStatus?.status ?? "unknown", tone: providerStatus?.status === "ok" ? "good" : "high" },
            { label: "Provider jobs", value: jobs.length },
            { label: "Config snapshot", value: projectConfig ? "Saved" : "Default" },
            { label: "Active tokens", value: tokensQuery.data?.active_count ?? 0, tone: tokensQuery.data?.active_count ? "good" : "neutral" }
          ]}
        />

        {success ? (
          <div className="action-banner">
            <CheckCircle2 aria-hidden="true" size={16} />
            <span>{success}</span>
          </div>
        ) : null}
        {error ? <div className="action-banner is-error">{error}</div> : null}

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Provider updates</span>
              <h3>Refresh stored provider data</h3>
            </div>
            <RefreshCw aria-hidden="true" size={18} />
          </div>
          <form className="form-grid" onSubmit={createProviderJob}>
            {providerSources.map((source) => (
              <label className="checkbox-row" key={source}>
                <input
                  type="checkbox"
                  checked={sources[source]}
                  onChange={(event) => setSources({ ...sources, [source]: event.target.checked })}
                />
                {source.toUpperCase()}
              </label>
            ))}
            <label>
              Max CVEs
              <input
                type="number"
                min={1}
                max={500}
                value={maxCves}
                onChange={(event) => setMaxCves(event.target.value)}
                placeholder="All current findings"
              />
            </label>
            <label className="checkbox-row">
              <input type="checkbox" checked={cacheOnly} onChange={(event) => setCacheOnly(event.target.checked)} />
              Cache-only
            </label>
            <label className="full-span">
              CVE allowlist
              <textarea
                value={cveIds}
                onChange={(event) => setCveIds(event.target.value)}
                placeholder="Optional: CVE-2024-3094, CVE-2023-..."
              />
            </label>
            <p className="field-help full-span">
              Jobs run synchronously and preserve the previous snapshot when refresh fails.
            </p>
            <div className="button-row">
              <button className="icon-text-button primary" type="submit" disabled={submittingAction === "provider-job"}>
                <RefreshCw aria-hidden="true" size={16} />
                {submittingAction === "provider-job" ? "Starting" : "Start provider update"}
              </button>
            </div>
          </form>
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>{formatCount(jobs.length)} jobs</span>
              <h3>Provider update history</h3>
            </div>
          </div>
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Provider update jobs</caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Sources</th>
                  <th scope="col">Started</th>
                  <th scope="col">Finished</th>
                  <th scope="col">Snapshot</th>
                  <th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job.id}>
                    <td>
                      <Badge tone={job.status === "failed" ? "critical" : "good"}>{job.status}</Badge>
                    </td>
                    <td>{job.requested_sources.join(", ") || "N.A."}</td>
                    <td>{formatDateTime(job.started_at)}</td>
                    <td>{formatDateTime(job.finished_at)}</td>
                    <td>{compactHash(metadataString(job.metadata, "new_snapshot_hash") ?? metadataString(job.metadata, "previous_snapshot_hash"))}</td>
                    <td>{job.error_message || metadataString(job.metadata, "detail") || metadataString(job.metadata, "mode") || "N.A."}</td>
                  </tr>
                ))}
                {jobs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="table-empty">
                      No provider update jobs have run.
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
              <span>Config as code</span>
              <h3>Project runtime defaults</h3>
            </div>
            <FileJson aria-hidden="true" size={18} />
          </div>
          <form className="form-stack" onSubmit={saveProjectConfig}>
            <label>
              Runtime config JSON
              <textarea
                value={configDraft}
                onChange={(event) => setConfigDraft(event.target.value)}
                spellCheck={false}
                rows={12}
              />
            </label>
            <p className="field-help">
              Latest snapshot: {projectConfig ? `${compactHash(projectConfig.id)} from ${formatDateTime(projectConfig.created_at)}` : "built-in default"}
            </p>
            <div className="button-row">
              <button className="icon-text-button" type="button" onClick={() => setConfigDraft(configDraftSource)}>
                Reset draft
              </button>
              <button className="icon-text-button primary" type="submit" disabled={submittingAction === "config-save"}>
                <FileJson aria-hidden="true" size={16} />
                {submittingAction === "config-save" ? "Saving" : "Save config snapshot"}
              </button>
            </div>
          </form>
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>GitHub issues</span>
              <h3>Preview and export remediation work</h3>
            </div>
            <Github aria-hidden="true" size={18} />
          </div>
          <form className="form-grid" onSubmit={previewGithubIssues}>
            <label>
              Priority
              <select value={githubPriority} onChange={(event) => setGithubPriority(event.target.value)}>
                <option value="">All priorities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </label>
            <label>
              Limit
              <input
                type="number"
                min={1}
                max={100}
                value={githubLimit}
                onChange={(event) => setGithubLimit(event.target.value)}
              />
            </label>
            <label>
              Label prefix
              <input value={githubLabelPrefix} onChange={(event) => setGithubLabelPrefix(event.target.value)} />
            </label>
            <label>
              Milestone
              <input value={githubMilestone} onChange={(event) => setGithubMilestone(event.target.value)} placeholder="Optional" />
            </label>
            <label>
              Repository
              <input value={githubRepository} onChange={(event) => setGithubRepository(event.target.value)} placeholder="owner/repo" />
            </label>
            <label>
              Token environment
              <input value={githubTokenEnv} onChange={(event) => setGithubTokenEnv(event.target.value)} placeholder="GITHUB_TOKEN" />
            </label>
            <p className="field-help full-span">
              Preview is local-only. Create uses the configured token environment variable on the server and never sends token values to the browser.
            </p>
            <div className="button-row">
              <button className="icon-text-button" type="submit" disabled={submittingAction === "github-preview"}>
                <Github aria-hidden="true" size={16} />
                {submittingAction === "github-preview" ? "Previewing" : "Preview issues"}
              </button>
              <button className="icon-text-button" type="button" onClick={() => void exportGithubIssues(true)} disabled={submittingAction === "github-dry-run"}>
                Dry-run export
              </button>
              <button className="icon-text-button primary" type="button" onClick={() => void exportGithubIssues(false)} disabled={submittingAction === "github-export"}>
                Create issues
              </button>
            </div>
          </form>
          {githubPreview ? <GitHubIssueTable items={githubPreview.items} /> : null}
          {githubExport ? <GitHubIssueTable items={githubExport.items} /> : null}
        </section>

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>API tokens</span>
              <h3>Mutation access control</h3>
            </div>
            <KeyRound aria-hidden="true" size={18} />
          </div>
          <form className="filter-panel" onSubmit={createToken}>
            <label>
              Token name
              <input
                required
                value={tokenName}
                onChange={(event) => setTokenName(event.target.value)}
                placeholder="automation"
              />
            </label>
            <div className="filter-actions">
              <button className="icon-text-button primary" type="submit" disabled={submittingAction === "token-create"}>
                <KeyRound aria-hidden="true" size={16} />
                {submittingAction === "token-create" ? "Creating" : "Create token"}
              </button>
            </div>
          </form>
          {newToken ? (
            <div className="status-copy">
              <span>Token value for {newToken.name}. It is shown once.</span>
              <code className="secret-value">{newToken.token}</code>
              <div className="button-row">
                <button className="icon-text-button" type="button" onClick={() => void copyNewToken()}>
                  <ClipboardCopy aria-hidden="true" size={16} />
                  Copy token
                </button>
                <button className="icon-text-button primary" type="button" onClick={useNewTokenNow}>
                  <KeyRound aria-hidden="true" size={16} />
                  Use for this session
                </button>
              </div>
            </div>
          ) : null}
          <TokenTable tokens={tokens} submittingAction={submittingAction} onRevoke={(token) => void revokeToken(token)} />
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <h2>Provider sources</h2>
          <ProviderChips status={providerStatus} />
          <div className="dense-table-wrap">
            <table className="dense-table">
              <caption className="sr-only">Provider source status</caption>
              <thead>
                <tr>
                  <th scope="col">Source</th>
                  <th scope="col">Available</th>
                  <th scope="col">Value</th>
                </tr>
              </thead>
              <tbody>
                {(providerStatus?.sources ?? []).map((source) => (
                  <tr key={source.name}>
                    <th scope="row" className="row-header">{source.name.toUpperCase()}</th>
                    <td>{source.available ? "Yes" : "No"}</td>
                    <td>{source.value || "N.A."}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rail-section">
          <h2>Runtime storage</h2>
          <div className="rail-list">
            <div className="rail-row">
              <span>Provider cache</span>
              <small>{providerStatus?.cache_dir ?? "N.A."}</small>
            </div>
            <div className="rail-row">
              <span>Snapshot directory</span>
              <small>{providerStatus?.snapshot_dir ?? "N.A."}</small>
            </div>
            <div className="rail-row">
              <span>Latest snapshot</span>
              <small>{compactHash(providerStatus?.snapshot.content_hash)}</small>
            </div>
          </div>
        </section>

        <section className="rail-section">
          <h2>Warnings</h2>
          {(providerStatus?.warnings ?? []).map((warning) => (
            <p className="rail-warning" key={warning}>
              {warning}
            </p>
          ))}
          {providerStatus?.warnings.length === 0 ? <p className="muted">No provider warnings.</p> : null}
        </section>
      </aside>
    </main>
  );
}

function GitHubIssueTable({
  items
}: {
  items: Array<GitHubIssuePreviewItem | GitHubIssueExportItem>;
}) {
  return (
    <div className="dense-table-wrap">
      <table className="dense-table">
        <caption className="sr-only">GitHub issue export preview</caption>
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col">Title</th>
            <th scope="col">Labels</th>
            <th scope="col">Milestone</th>
            <th scope="col">Issue</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.duplicate_key}>
              <td>{issueStatus(item)}</td>
              <td>{item.title}</td>
              <td>{item.labels.join(", ") || "N.A."}</td>
              <td>{item.milestone || "N.A."}</td>
              <td>{issueUrl(item)}</td>
            </tr>
          ))}
          {items.length === 0 ? (
            <tr>
              <td colSpan={5} className="table-empty">
                No matching findings are ready for GitHub issue export.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

function TokenTable({
  tokens,
  submittingAction,
  onRevoke
}: {
  tokens: ApiTokenMetadata[];
  submittingAction: string | null;
  onRevoke: (token: ApiTokenMetadata) => void;
}) {
  return (
    <div className="dense-table-wrap">
      <table className="dense-table">
        <caption className="sr-only">API token metadata</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Status</th>
            <th scope="col">Created</th>
            <th scope="col">Last used</th>
            <th scope="col">Revoked</th>
            <th scope="col">Action</th>
          </tr>
        </thead>
        <tbody>
          {tokens.map((token) => (
            <tr key={token.id}>
              <th scope="row" className="row-header">{token.name}</th>
              <td>
                <Badge tone={token.active ? "good" : "neutral"}>{token.active ? "active" : "revoked"}</Badge>
              </td>
              <td>{formatDateTime(token.created_at)}</td>
              <td>{formatDateTime(token.last_used_at)}</td>
              <td>{formatDateTime(token.revoked_at)}</td>
              <td>
                <button
                  className="icon-button"
                  type="button"
                  disabled={!token.active || submittingAction === `token:${token.id}`}
                  onClick={() => onRevoke(token)}
                  aria-label={`Revoke token ${token.name}`}
                >
                  <Trash2 aria-hidden="true" size={16} />
                </button>
              </td>
            </tr>
          ))}
          {tokens.length === 0 ? (
            <tr>
              <td colSpan={6} className="table-empty">
                No API tokens have been created.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

function issueStatus(item: GitHubIssuePreviewItem | GitHubIssueExportItem): string {
  return "status" in item ? item.status : "preview";
}

function issueUrl(item: GitHubIssuePreviewItem | GitHubIssueExportItem): string {
  return "issue_url" in item && item.issue_url ? item.issue_url : "N.A.";
}

function metadataString(metadata: Record<string, unknown>, key: string): string | undefined {
  const value = metadata[key];
  return typeof value === "string" && value ? value : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed.";
}
