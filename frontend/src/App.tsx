import { Navigate, Route, Routes } from "react-router-dom";

import AppShell from "./components/AppShell";
import ArtifactsPage from "./pages/ArtifactsPage";
import AssetsPage from "./pages/AssetsPage";
import CoveragePage from "./pages/CoveragePage";
import DashboardPage from "./pages/DashboardPage";
import EvidenceVerifyPage from "./pages/EvidenceVerifyPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import FindingsPage from "./pages/FindingsPage";
import GovernancePage from "./pages/GovernancePage";
import ImportPage from "./pages/ImportPage";
import NotFoundPage from "./pages/NotFoundPage";
import ProjectCreatePage from "./pages/ProjectCreatePage";
import ProjectBootstrap from "./pages/ProjectBootstrap";
import ProjectsPage from "./pages/ProjectsPage";
import FindingRedirectPage from "./pages/FindingRedirectPage";
import RunRedirectPage from "./pages/RunRedirectPage";
import RunArtifactsPage from "./pages/RunArtifactsPage";
import SettingsPage from "./pages/SettingsPage";
import TechniqueDetailPage from "./pages/TechniqueDetailPage";
import VulnerabilityLookupPage from "./pages/VulnerabilityLookupPage";
import WaiversPage from "./pages/WaiversPage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<ProjectBootstrap />} />
      <Route path="/new" element={<ProjectCreatePage />} />
      <Route path="/projects" element={<ProjectsPage />} />
      <Route path="/findings/:findingId" element={<FindingRedirectPage />} />
      <Route path="/analysis-runs/:runId/reports" element={<RunRedirectPage />} />
      <Route path="/runs/:runId/artifacts" element={<RunRedirectPage />} />
      <Route path="/evidence-bundles/:bundleId/verify" element={<EvidenceVerifyPage />} />
      <Route path="/projects/:projectId" element={<AppShell />}>
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="imports/new" element={<ImportPage />} />
        <Route path="artifacts" element={<ArtifactsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:findingId" element={<FindingDetailPage />} />
        <Route path="governance" element={<GovernancePage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="waivers" element={<WaiversPage />} />
        <Route path="coverage" element={<CoveragePage />} />
        <Route path="attack/techniques/:techniqueId" element={<TechniqueDetailPage />} />
        <Route path="vulnerabilities" element={<VulnerabilityLookupPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="runs/:runId/artifacts" element={<RunArtifactsPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
