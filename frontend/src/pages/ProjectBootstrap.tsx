import { Link, Navigate } from "react-router-dom";

import EmptyState from "../components/EmptyState";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { useProjects } from "../hooks/useWorkbenchQueries";

export default function ProjectBootstrap() {
  const projectsQuery = useProjects();

  if (projectsQuery.isLoading) {
    return <LoadingPanel as="main" label="Loading projects" />;
  }

  if (projectsQuery.error) {
    return <ErrorPanel as="main" error={projectsQuery.error} />;
  }

  const projects = projectsQuery.data?.items ?? [];

  if (projects.length === 1) {
    return <Navigate to={`/projects/${projects[0].id}/dashboard`} replace />;
  }

  if (projects.length > 1) {
    return <Navigate to="/projects" replace />;
  }

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
