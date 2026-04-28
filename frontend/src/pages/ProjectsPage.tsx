import { FolderPlus, LayoutDashboard } from "lucide-react";
import { Link } from "react-router-dom";

import EmptyState from "../components/EmptyState";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { formatDateTime } from "../lib/format";
import { useProjects } from "../hooks/useWorkbenchQueries";

export default function ProjectsPage() {
  const projectsQuery = useProjects();

  if (projectsQuery.isLoading) {
    return <LoadingPanel as="main" label="Loading projects" />;
  }

  if (projectsQuery.error) {
    return <ErrorPanel as="main" error={projectsQuery.error} />;
  }

  const projects = projectsQuery.data?.items ?? [];

  if (projects.length === 0) {
    return (
      <main className="bootstrap-page">
        <EmptyState
          title="No project exists yet"
          action={
            <Link className="icon-text-button primary" to="/new">
              Create project
            </Link>
          }
        >
          Create the first Workbench project, then import vulnerability evidence.
        </EmptyState>
      </main>
    );
  }

  return (
    <main className="standalone-page">
      <section className="section-heading">
        <span>Workspace</span>
        <h2>Projects</h2>
      </section>

      <div className="inline-actions">
        <Link className="icon-text-button primary" to="/new">
          <FolderPlus aria-hidden="true" size={16} />
          New project
        </Link>
      </div>

      <section className="panel-section">
        <div className="panel-heading">
          <div>
            <span>{projects.length} workspaces</span>
            <h3>Available triage projects</h3>
          </div>
        </div>
        <div className="dense-table-wrap">
          <table className="dense-table project-table">
            <thead>
              <tr>
                <th scope="col">Project</th>
                <th scope="col">Description</th>
                <th scope="col">Created</th>
                <th scope="col">
                  <span className="sr-only">Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id}>
                  <th scope="row">
                    <Link className="table-link" to={`/projects/${project.id}/dashboard`}>
                      {project.name}
                    </Link>
                  </th>
                  <td>{project.description || <span className="muted">No description</span>}</td>
                  <td>{formatDateTime(project.created_at)}</td>
                  <td>
                    <Link className="icon-text-button" to={`/projects/${project.id}/dashboard`}>
                      <LayoutDashboard aria-hidden="true" size={16} />
                      Open
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
