import { ClipboardList, FileUp, LockKeyhole, Upload } from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";

import { apiPostForm } from "../api/client";
import type { AnalysisRun } from "../api/types";
import KpiStrip from "../components/KpiStrip";
import ProviderChips from "../components/ProviderChips";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { formatBytes, formatDateTime } from "../lib/format";
import {
  useProject,
  useProviderStatus,
  useWorkbenchArtifacts,
  useWorkbenchBootstrap
} from "../hooks/useWorkbenchQueries";

const fallbackInputFormats = ["cve-list", "generic-occurrence-csv", "trivy-json", "grype-json"];

export default function ImportPage() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const projectQuery = useProject(projectId);
  const bootstrapQuery = useWorkbenchBootstrap();
  const artifactsQuery = useWorkbenchArtifacts();
  const providerQuery = useProviderStatus();
  const [inputFormat, setInputFormat] = useState("cve-list");
  const [providerSnapshotFile, setProviderSnapshotFile] = useState("");
  const [lockedProviderData, setLockedProviderData] = useState(false);
  const [attackSource, setAttackSource] = useState("none");
  const [attackMappingFile, setAttackMappingFile] = useState("");
  const [attackTechniqueMetadataFile, setAttackTechniqueMetadataFile] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const inputFormats = useMemo(
    () => bootstrapQuery.data?.supported_input_formats ?? fallbackInputFormats,
    [bootstrapQuery.data?.supported_input_formats]
  );

  const providerSnapshots = artifactsQuery.data?.provider_snapshots ?? [];
  const attackArtifacts = artifactsQuery.data?.attack_artifacts ?? [];

  async function submitImport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectId) {
      setError(new Error("Project id is required."));
      return;
    }

    const form = event.currentTarget;
    const formData = new FormData(form);
    formData.set("input_format", inputFormat);
    formData.set("locked_provider_data", String(lockedProviderData));
    formData.set("attack_source", attackSource);
    setOptionalText(formData, "provider_snapshot_file", providerSnapshotFile);
    setOptionalText(formData, "attack_mapping_file", attackMappingFile);
    setOptionalText(formData, "attack_technique_metadata_file", attackTechniqueMetadataFile);

    setError(null);
    setSuccess(null);
    setSubmitting(true);

    try {
      const run = await apiPostForm<AnalysisRun>(`/api/projects/${projectId}/imports`, formData);
      setSuccess(`Import completed with ${run.summary.findings_count} findings.`);
      await queryClient.invalidateQueries({ queryKey: ["runs", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard", projectId] });
      navigate(`/projects/${projectId}/runs/${run.id}/artifacts`);
    } catch (caught) {
      setError(caught);
    } finally {
      setSubmitting(false);
    }
  }

  if (projectQuery.isLoading) {
    return <LoadingPanel label="Loading project" />;
  }

  if (projectQuery.error) {
    return <ErrorPanel error={projectQuery.error} />;
  }

  return (
    <main className="page-grid">
      <section className="content-column">
        <div className="section-heading">
          <span>Import</span>
          <h2>{projectQuery.data?.name ?? "Project"}</h2>
        </div>

        <KpiStrip
          items={[
            { label: "Input formats", value: inputFormats.length },
            { label: "Snapshots", value: providerSnapshots.length },
            { label: "ATT&CK artifacts", value: attackArtifacts.length },
            { label: "Provider lock", value: lockedProviderData ? "On" : "Off", tone: lockedProviderData ? "good" : "neutral" }
          ]}
        />

        <section className="panel-section">
          <div className="panel-heading">
            <div>
              <span>Upload</span>
              <h3>Start analysis run</h3>
            </div>
            <FileUp aria-hidden="true" size={18} />
          </div>

          {error ? <ErrorPanel error={error} /> : null}
          {success ? <div className="action-banner">{success}</div> : null}

          <form className="form-grid" onSubmit={submitImport}>
            <label>
              Input format
              <select
                name="input_format"
                value={inputFormat}
                onChange={(event) => setInputFormat(event.target.value)}
              >
                {inputFormats.map((format) => (
                  <option value={format} key={format}>
                    {formatLabel(format)}
                  </option>
                ))}
              </select>
            </label>

            <label>
              File
              <input required type="file" name="file" />
            </label>

            <label className="full-span">
              Provider snapshot
              <input
                name="provider_snapshot_file"
                value={providerSnapshotFile}
                onChange={(event) => setProviderSnapshotFile(event.target.value)}
                list="provider-snapshots"
                placeholder="demo_provider_snapshot.json"
              />
              <span className="field-help">Leave empty to use live provider cache when the server permits it.</span>
            </label>

            <label className="checkbox-row full-span">
              <input
                type="checkbox"
                name="locked_provider_data"
                checked={lockedProviderData}
                onChange={(event) => setLockedProviderData(event.target.checked)}
              />
              Locked provider data
            </label>

            <label>
              ATT&CK source
              <select name="attack_source" value={attackSource} onChange={(event) => setAttackSource(event.target.value)}>
                <option value="none">None</option>
                <option value="ctid-json">CTID JSON</option>
              </select>
            </label>

            <label>
              ATT&CK mapping file
              <input
                name="attack_mapping_file"
                value={attackMappingFile}
                onChange={(event) => setAttackMappingFile(event.target.value)}
                list="attack-artifacts"
                placeholder="ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"
                disabled={attackSource === "none"}
              />
            </label>

            <label>
              ATT&CK technique metadata
              <input
                name="attack_technique_metadata_file"
                value={attackTechniqueMetadataFile}
                onChange={(event) => setAttackTechniqueMetadataFile(event.target.value)}
                list="attack-artifacts"
                placeholder="attack_techniques_enterprise_16.1_subset.json"
                disabled={attackSource === "none"}
              />
            </label>

            <label>
              Asset context
              <input type="file" name="asset_context_file" accept=".csv,text/csv" />
            </label>

            <label>
              VEX document
              <input type="file" name="vex_file" accept=".json,application/json" />
            </label>

            <label>
              Waiver file
              <input type="file" name="waiver_file" accept=".yml,.yaml,text/yaml,application/x-yaml" />
            </label>

            <datalist id="provider-snapshots">
              {providerSnapshots.map((artifact) => (
                <option value={artifact.filename} key={artifact.filename} />
              ))}
            </datalist>
            <datalist id="attack-artifacts">
              {attackArtifacts.map((artifact) => (
                <option value={artifact.filename} key={artifact.filename} />
              ))}
            </datalist>

            <div className="button-row">
              <button className="icon-text-button primary" type="submit" disabled={submitting}>
                <Upload aria-hidden="true" size={16} />
                {submitting ? "Importing" : "Start import"}
              </button>
            </div>
          </form>
        </section>
      </section>

      <aside className="intelligence-rail">
        <section className="rail-section">
          <div className="rail-title">
            <ClipboardList aria-hidden="true" size={18} />
            <h2>Available snapshots</h2>
          </div>
          {artifactsQuery.isLoading ? <p className="muted">Loading artifact options.</p> : null}
          {artifactsQuery.error ? <ErrorPanel error={artifactsQuery.error} /> : null}
          <div className="rail-list">
            {providerSnapshots.slice(0, 6).map((artifact) => (
              <div className="rail-row" key={artifact.filename}>
                <span>{artifact.filename}</span>
                <strong>{formatBytes(artifact.size_bytes)}</strong>
                <small>{formatDateTime(artifact.modified_at)}</small>
                <button
                  className="icon-text-button"
                  type="button"
                  onClick={() => setProviderSnapshotFile(artifact.filename)}
                  aria-label={`Use snapshot file ${artifact.filename}`}
                >
                  Use
                </button>
              </div>
            ))}
            {providerSnapshots.length === 0 && !artifactsQuery.isLoading ? (
              <p className="muted">No provider snapshots discovered.</p>
            ) : null}
          </div>
        </section>

        <section className="rail-section">
          <div className="rail-title">
            <LockKeyhole aria-hidden="true" size={18} />
            <h2>Provider status</h2>
          </div>
          <ProviderChips status={providerQuery.data} />
        </section>

        <section className="rail-section">
          <h2>Project</h2>
          <div className="rail-list">
            <div className="rail-row">
              <span>{projectQuery.data?.name ?? "Project"}</span>
              <strong>{projectQuery.data?.id.slice(0, 8) ?? "N.A."}</strong>
              <small>{projectQuery.data?.description ?? "No description"}</small>
            </div>
          </div>
          {projectId ? (
            <Link className="icon-text-button" to={`/projects/${projectId}/dashboard`}>
              Dashboard
            </Link>
          ) : null}
        </section>
      </aside>
    </main>
  );
}

function setOptionalText(formData: FormData, name: string, value: string) {
  const trimmed = value.trim();
  if (trimmed) {
    formData.set(name, trimmed);
  } else {
    formData.delete(name);
  }
}

function formatLabel(value: string): string {
  return value
    .split("-")
    .map((part) => part.toUpperCase() === "CVE" ? "CVE" : part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}
