import { useParams } from "react-router-dom";

import { apiGet } from "../api/client";
import type { EvidenceBundleVerificationResponse } from "../api/types";
import { Badge } from "../components/Badges";
import { ErrorPanel, LoadingPanel } from "../components/QueryState";
import { compactHash } from "../lib/format";
import { useQuery } from "@tanstack/react-query";

export default function EvidenceVerifyPage() {
  const { bundleId } = useParams();
  const verifyQuery = useQuery({
    queryKey: ["evidence-verify", bundleId],
    queryFn: () => apiGet<EvidenceBundleVerificationResponse>(`/api/evidence-bundles/${bundleId}/verify`),
    enabled: Boolean(bundleId)
  });

  if (verifyQuery.isLoading) {
    return <LoadingPanel label="Verifying evidence bundle" />;
  }

  if (verifyQuery.error) {
    return <ErrorPanel error={verifyQuery.error} />;
  }

  const result = verifyQuery.data;
  const ok = result?.summary.ok === true;

  return (
    <main className="bootstrap-page">
      <section className="panel-section narrow-panel">
        <div className="panel-heading">
          <div>
            <span>Evidence verification</span>
            <h3>{ok ? "Bundle integrity passed" : "Bundle requires review"}</h3>
          </div>
          <Badge tone={ok ? "good" : "critical"}>{ok ? "ok" : "review"}</Badge>
        </div>
        <dl className="definition-grid">
          {Object.entries(result?.summary ?? {}).map(([key, value]) => (
            <div key={key}>
              <dt>{key.replaceAll("_", " ")}</dt>
              <dd>{String(value)}</dd>
            </div>
          ))}
        </dl>
        <div className="dense-table-wrap">
          <table className="dense-table">
            <caption className="sr-only">Evidence bundle verification items</caption>
            <thead>
              <tr>
                <th scope="col">Path</th>
                <th scope="col">Status</th>
                <th scope="col">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {(result?.items ?? []).map((item, index) => (
                <tr key={`${String(item.path ?? "item")}-${index}`}>
                  <th scope="row" className="row-header">{String(item.path ?? "N.A.")}</th>
                  <td>{String(item.status ?? item.ok ?? "N.A.")}</td>
                  <td>{compactHash(String(item.sha256 ?? item.expected_sha256 ?? ""))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
