import { Navigate, useParams } from "react-router-dom";

import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { useFinding } from "../hooks/useWorkbenchQueries";

export default function FindingRedirectPage() {
  const { findingId } = useParams();
  const findingQuery = useFinding(findingId);

  if (findingQuery.isLoading) {
    return <LoadingPanel as="main" label="Resolving finding" />;
  }

  if (findingQuery.error) {
    return <ErrorPanel as="main" error={findingQuery.error} />;
  }

  const finding = findingQuery.data;
  if (!finding) {
    return <ErrorPanel as="main" error={new Error("Finding not found.")} />;
  }

  return <Navigate to={`/projects/${finding.project_id}/findings/${finding.id}`} replace />;
}
