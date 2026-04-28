import { Link } from "react-router-dom";

import EmptyState from "../components/EmptyState";

export default function NotFoundPage() {
  return (
    <main className="bootstrap-page">
      <EmptyState
        title="Workbench route not found"
        action={
          <Link className="icon-text-button primary" to="/">
            Open workbench
          </Link>
        }
      >
        The requested React Workbench route is not available.
      </EmptyState>
    </main>
  );
}
