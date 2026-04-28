import { Navigate, useParams } from "react-router-dom";

import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { useRunArtifacts } from "../hooks/useWorkbenchQueries";

export default function RunRedirectPage() {
  const { runId } = useParams();
  const artifactsQuery = useRunArtifacts(runId);

  if (artifactsQuery.isLoading) {
    return <LoadingPanel as="main" label="Resolving run" />;
  }

  if (artifactsQuery.error) {
    return <ErrorPanel as="main" error={artifactsQuery.error} />;
  }

  const run = artifactsQuery.data?.run;
  if (!run) {
    return <ErrorPanel as="main" error={new Error("Analysis run not found.")} />;
  }

  return <Navigate to={`/projects/${run.project_id}/runs/${run.id}/artifacts`} replace />;
}
