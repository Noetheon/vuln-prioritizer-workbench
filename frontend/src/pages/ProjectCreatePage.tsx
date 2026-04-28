import { FolderPlus } from "lucide-react";
import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

import { apiPost } from "../api/client";
import type { Project } from "../api/types";
import { ErrorPanel } from "../components/QueryState";

export default function ProjectCreatePage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submitProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSuccess(null);
    setSubmitting(true);

    try {
      const project = await apiPost<Project>("/api/projects", {
        name: name.trim(),
        description: description.trim() || null
      });
      setSuccess(`Created ${project.name}.`);
      navigate(`/projects/${project.id}/dashboard`);
    } catch (caught) {
      setError(caught);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="bootstrap-page">
      <section className="panel-section">
        <div className="panel-heading">
          <div>
            <span>Workspace</span>
            <h3>Create project</h3>
          </div>
          <FolderPlus aria-hidden="true" size={20} />
        </div>

        {error ? <ErrorPanel error={error} /> : null}
        {success ? <div className="action-banner">{success}</div> : null}

        <form className="form-grid" onSubmit={submitProject}>
          <label className="full-span">
            Project name
            <input
              required
              autoComplete="off"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="online-shop-demo"
            />
          </label>
          <label className="full-span">
            Description
            <textarea
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              rows={4}
            />
          </label>
          <div className="button-row">
            <button className="icon-text-button primary" type="submit" disabled={submitting}>
              <FolderPlus aria-hidden="true" size={16} />
              {submitting ? "Creating" : "Create project"}
            </button>
          </div>
        </form>
      </section>
    </main>
  );
}
