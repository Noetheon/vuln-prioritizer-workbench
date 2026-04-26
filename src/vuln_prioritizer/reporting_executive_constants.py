"""Executive report constants and stylesheet."""

from __future__ import annotations

PRIORITY_ORDER = ("Critical", "High", "Medium", "Low")
PRIORITY_TONES = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}
SECTION_NAV = [
    ("executive-brief", "Executive Security Overview"),
    ("risk-posture", "Risk Posture and Source Signals"),
    ("priority-findings", "Priority Findings"),
    ("attack-context", "MITRE ATT&CK Threat Context"),
    ("remediation-plan", "Executive Actions and Remediation Plan"),
    ("evidence-quality", "Evidence, Data Quality and Methodology"),
]


EXECUTIVE_REPORT_CSS = """
:root {
  color-scheme: light;
  --er-bg: #f5f7fb;
  --er-surface: #ffffff;
  --er-text: #07183d;
  --er-muted: #52627a;
  --er-line: #d9e2ef;
  --er-blue: #0b63f6;
  --er-critical: #dc2626;
  --er-high: #f97316;
  --er-medium: #d99a07;
  --er-low: #64748b;
  --er-success: #059669;
  --er-accent: #6d28d9;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

* { box-sizing: border-box; }

.executive-report-page {
  min-width: 0;
  margin: 0;
  background:
    linear-gradient(180deg, rgba(234, 242, 255, 0.72), rgba(245, 247, 251, 0) 260px),
    var(--er-bg);
  color: var(--er-text);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

.er-app-header {
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  min-height: 66px;
  align-items: center;
  padding: 0 32px;
  border-bottom: 1px solid rgba(217, 226, 239, 0.92);
  background: rgba(255, 255, 255, 0.94);
  box-shadow: 0 10px 28px rgba(7, 24, 61, 0.035);
  backdrop-filter: blur(14px);
}

.er-app-brand {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  gap: 12px;
  color: var(--er-text);
  font-size: 16px;
  font-weight: 900;
  overflow-wrap: anywhere;
  text-decoration: none;
}

.er-app-brand-logo,
.project-emblem,
.nav-icon {
  display: inline-grid;
  flex: 0 0 auto;
  place-items: center;
  color: var(--er-blue);
}

.er-app-brand-logo {
  width: 38px;
  height: 44px;
}

.er-app-brand-logo svg {
  width: 38px;
  height: 44px;
}

.shield-logo {
  display: block;
  overflow: visible;
}

.shield-logo-fill {
  fill: currentColor;
  filter: drop-shadow(0 8px 15px rgba(11, 99, 246, 0.16));
}

.shield-logo-check {
  fill: none;
  stroke: #ffffff;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 5.2;
}

.er-shell {
  width: min(1440px, calc(100vw - 40px));
  margin: 0 auto;
  max-width: 100%;
  overflow-x: hidden;
  padding: 28px 0 56px;
}

.er-app-layout {
  width: min(1660px, calc(100vw - 32px));
  margin: 0 auto;
  max-width: 100%;
}

.er-app-layout.has-workspace-nav {
  display: grid;
  grid-template-columns: 230px minmax(0, 1fr);
  gap: 26px;
  align-items: start;
  transition:
    grid-template-columns 180ms ease,
    gap 180ms ease;
}

.sidebar-collapsed .er-app-layout.has-workspace-nav {
  grid-template-columns: 76px minmax(0, 1fr);
  gap: 20px;
}

.er-app-layout.has-workspace-nav .er-shell {
  width: 100%;
  min-width: 0;
}

.er-workspace-sidebar {
  position: sticky;
  top: 82px;
  display: grid;
  max-height: calc(100vh - 98px);
  overflow-y: auto;
  padding: 22px 12px 32px;
  transition: padding 180ms ease;
}

.sidebar-collapsed .er-workspace-sidebar {
  padding-inline: 8px;
}

.sidebar-toggle {
  display: flex;
  width: 100%;
  min-height: 38px;
  align-items: center;
  justify-content: flex-start;
  gap: 10px;
  margin: 0 0 12px;
  padding: 0 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.72);
  color: #405373;
  font: inherit;
  font-size: 13px;
  font-weight: 850;
  line-height: 1;
  box-shadow: 0 6px 18px rgba(7, 24, 61, 0.035);
  cursor: pointer;
}

.sidebar-toggle:hover {
  border-color: var(--er-blue);
  background: #eaf2ff;
  color: var(--er-blue);
}

.sidebar-toggle-icon {
  position: relative;
  display: inline-block;
  width: 20px;
  height: 20px;
  flex: 0 0 auto;
}

.sidebar-toggle-icon::before,
.sidebar-toggle-icon::after {
  content: "";
  position: absolute;
  inset: 4px 5px;
  border: solid currentColor;
  border-width: 0 2px 2px 0;
  transform: rotate(135deg);
}

.sidebar-toggle-icon::after {
  inset: 4px 10px 4px 0;
  opacity: 0.45;
}

.sidebar-collapsed .sidebar-toggle {
  justify-content: center;
  padding: 0;
}

.sidebar-collapsed .sidebar-toggle-icon::before,
.sidebar-collapsed .sidebar-toggle-icon::after {
  transform: rotate(-45deg);
}

.sidebar-collapsed .sidebar-toggle-text,
.sidebar-collapsed .nav-label,
.sidebar-collapsed .project-copy {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}

.er-workspace-project {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 10px;
  margin-bottom: 18px;
  padding: 12px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.72);
  box-shadow: 0 6px 18px rgba(7, 24, 61, 0.035);
}

.project-emblem {
  width: 30px;
  height: 34px;
}

.project-emblem .shield-logo {
  width: 30px;
  height: 34px;
}

.project-copy {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.project-copy span,
.er-workspace-nav-group p {
  margin: 0;
  color: var(--er-muted);
  font-size: 0.72rem;
  font-weight: 850;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.project-copy strong {
  min-width: 0;
  color: var(--er-text);
  overflow-wrap: anywhere;
  font-size: 0.94rem;
  line-height: 1.25;
}

.sidebar-collapsed .er-workspace-project {
  justify-content: center;
  padding: 12px 0;
}

.er-workspace-nav,
.er-workspace-nav-group {
  display: grid;
}

.er-workspace-nav {
  gap: 18px;
}

.er-workspace-nav-group {
  gap: 5px;
}

.sidebar-collapsed .er-workspace-nav-group {
  gap: 7px;
}

.sidebar-collapsed .er-workspace-nav-group p {
  height: 1px;
  margin: 4px 12px;
  padding: 0;
  overflow: hidden;
  background: var(--er-line);
  color: transparent;
}

.er-workspace-nav-group a {
  position: relative;
  display: flex;
  min-height: 39px;
  min-width: 0;
  align-items: center;
  gap: 10px;
  padding: 0 10px;
  border-radius: 7px;
  color: #405373;
  font-size: 0.88rem;
  font-weight: 800;
  text-decoration: none;
}

.nav-icon {
  width: 24px;
  height: 24px;
}

.nav-icon svg {
  width: 20px;
  height: 20px;
  fill: currentColor;
}

.nav-label {
  min-width: 0;
  overflow-wrap: anywhere;
}

.er-workspace-nav-group a:hover,
.er-workspace-nav-group a[aria-current="page"] {
  background: #eaf2ff;
  color: var(--er-blue);
}

.er-workspace-nav-group a[aria-current="page"]::before {
  content: "";
  position: absolute;
  inset: 8px auto 8px 0;
  width: 3px;
  border-radius: 999px;
  background: var(--er-blue);
}

.sidebar-collapsed .er-workspace-nav-group a {
  justify-content: center;
  min-height: 44px;
  padding: 0;
}

.sidebar-collapsed .er-workspace-nav-group a[aria-current="page"]::before {
  inset: 9px auto 9px 0;
}

.er-hero,
.er-section,
.er-panel,
.er-kpi {
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: var(--er-surface);
}

.er-hero {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) minmax(250px, 340px);
  gap: 22px;
  padding: 28px;
}

.er-brand-mark {
  display: grid;
  width: 64px;
  height: 64px;
  place-items: center;
  border: 5px solid var(--er-blue);
  border-radius: 18px;
  color: var(--er-blue);
  font-size: 34px;
  font-weight: 900;
}

.er-eyebrow,
.er-muted,
.er-kpi span,
.er-kpi small,
.er-meta-panel span,
.er-table th {
  color: var(--er-muted);
}

.er-eyebrow {
  margin: 0 0 6px;
  font-size: 0.75rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.er-hero h1 {
  margin: 0;
  font-size: clamp(2.2rem, 5vw, 4.6rem);
  line-height: 0.95;
  letter-spacing: 0;
}

.er-subtitle {
  margin: 8px 0;
  color: var(--er-blue);
  font-size: 1.25rem;
  font-weight: 750;
}

.er-summary {
  max-width: 900px;
  margin: 14px 0 0;
  color: #23395f;
  line-height: 1.55;
}

.er-meta-panel {
  display: grid;
  align-content: start;
  gap: 8px;
  padding: 18px;
  border-left: 1px solid var(--er-line);
}

.er-meta-panel strong {
  overflow-wrap: anywhere;
}

.er-button,
.er-section-nav a,
.er-artifact {
  color: inherit;
  text-decoration: none;
}

.er-button {
  display: inline-flex;
  width: fit-content;
  min-height: 36px;
  align-items: center;
  margin-top: 8px;
  padding: 0 12px;
  border: 1px solid var(--er-line);
  border-radius: 6px;
  background: #eef5ff;
  color: var(--er-blue);
  font-weight: 750;
}

.er-section-nav {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 16px 0;
  padding: 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.96);
  contain: layout paint;
}

.er-section-nav a {
  padding: 8px 10px;
  border-radius: 6px;
  color: #25405f;
  font-size: 0.86rem;
  font-weight: 700;
}

.er-section-nav a:hover { background: #eef5ff; }

.er-sr-note {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

.er-section {
  margin-top: 16px;
  padding: 22px;
  scroll-margin-top: 76px;
}

.er-section-head {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--er-line);
  padding-bottom: 12px;
}

.er-section h2,
.er-panel h3,
.er-panel h4 {
  margin: 0;
  letter-spacing: 0;
}

.er-section h2 { font-size: clamp(1.4rem, 3vw, 2rem); }

.er-kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}

.er-kpi-grid.compact {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.er-kpi {
  min-width: 0;
  padding: 16px;
}

.er-kpi span,
.er-kpi small {
  display: block;
  font-size: 0.8rem;
  font-weight: 750;
}

.er-kpi strong {
  display: block;
  margin: 8px 0;
  color: var(--er-blue);
  font-size: 2rem;
  line-height: 1;
}

.er-kpi[data-tone="critical"] strong,
.er-badge[data-tone="critical"] { color: var(--er-critical); }
.er-kpi[data-tone="high"] strong,
.er-badge[data-tone="high"] { color: var(--er-high); }
.er-kpi[data-tone="medium"] strong,
.er-badge[data-tone="medium"] { color: var(--er-medium); }
.er-kpi[data-tone="success"] strong { color: var(--er-success); }
.er-kpi[data-tone="accent"] strong { color: var(--er-accent); }

.er-two-col,
.er-three-col {
  display: grid;
  gap: 14px;
}

.er-two-col { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
.er-three-col { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.er-top-rollups { margin-top: 14px; }

.er-panel {
  min-width: 0;
  padding: 18px;
}

.er-panel-accent {
  background: linear-gradient(180deg, #ffffff 0%, #f2f7ff 100%);
}

.er-panel p {
  line-height: 1.5;
}

.er-mini-list,
.er-bar-stack,
.er-artifact-list,
.er-warning-list {
  display: grid;
  gap: 10px;
}

.er-decision-item {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 10px;
  padding: 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: #fbfdff;
}

.er-decision-item p { margin: 4px 0 0; }

.er-badge {
  display: inline-flex;
  min-height: 26px;
  align-items: center;
  justify-content: center;
  padding: 0 9px;
  border-radius: 6px;
  background: #eef2f7;
  font-size: 0.82rem;
  font-weight: 850;
}

.er-bar-row {
  display: grid;
  grid-template-columns: minmax(100px, 1fr) minmax(80px, 2fr) auto;
  gap: 10px;
  align-items: center;
  font-size: 0.9rem;
}

.er-progress {
  width: 100%;
  height: 10px;
  overflow: hidden;
  border: 0;
  border-radius: 999px;
  background: #edf2f8;
}

.er-progress::-webkit-progress-bar {
  border-radius: 999px;
  background: #edf2f8;
}

.er-progress::-webkit-progress-value {
  border-radius: 999px;
  background: var(--er-blue);
}

.er-progress::-moz-progress-bar {
  border-radius: 999px;
  background: var(--er-blue);
}

.er-progress[data-tone="critical"]::-webkit-progress-value { background: var(--er-critical); }
.er-progress[data-tone="high"]::-webkit-progress-value { background: var(--er-high); }
.er-progress[data-tone="medium"]::-webkit-progress-value { background: var(--er-medium); }
.er-progress[data-tone="low"]::-webkit-progress-value { background: var(--er-low); }
.er-progress[data-tone="critical"]::-moz-progress-bar { background: var(--er-critical); }
.er-progress[data-tone="high"]::-moz-progress-bar { background: var(--er-high); }
.er-progress[data-tone="medium"]::-moz-progress-bar { background: var(--er-medium); }
.er-progress[data-tone="low"]::-moz-progress-bar { background: var(--er-low); }

.er-scatter {
  width: 100%;
  min-height: 220px;
  color: var(--er-muted);
  font-size: 12px;
}

.er-plot-bg { fill: #f8fbff; stroke: var(--er-line); }
.er-plot-line { stroke: #b8c7da; stroke-dasharray: 4 4; }
.er-dot { stroke-width: 2; }
.er-dot.critical { fill: var(--er-critical); }
.er-dot.high { fill: var(--er-high); }
.er-dot.medium { fill: var(--er-medium); }
.er-dot.low { fill: var(--er-blue); }

.er-table-wrap {
  max-width: 100%;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  scrollbar-gutter: stable;
  contain: layout paint;
  border: 1px solid var(--er-line);
  border-radius: 8px;
}

.er-table {
  width: 100%;
  min-width: min(980px, 100%);
  border-collapse: collapse;
  background: var(--er-surface);
}

.er-table th,
.er-table td {
  padding: 10px 11px;
  border-bottom: 1px solid var(--er-line);
  text-align: left;
  vertical-align: top;
  font-size: 0.88rem;
  line-height: 1.32;
}

.er-two-mini {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}

.er-detail-list {
  display: grid;
  grid-template-columns: minmax(120px, 0.7fr) minmax(0, 1fr);
  gap: 8px 12px;
}

.er-detail-list dt {
  color: var(--er-muted);
  font-weight: 750;
}

.er-detail-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.er-status-strip {
  display: flex;
  min-height: 76px;
  overflow: hidden;
  border: 1px solid var(--er-line);
  border-radius: 8px;
}

.er-status-segment {
  display: grid;
  min-width: 72px;
  place-items: center;
  padding: 10px;
  background: #eef5ff;
  color: var(--er-blue);
  text-align: center;
}

.er-status-segment[data-tone="critical"] { background: #fff1f2; color: var(--er-critical); }
.er-status-segment[data-tone="medium"] { background: #fffbeb; color: var(--er-medium); }
.er-status-segment[data-tone="low"] { background: #f1f5f9; color: var(--er-low); }

.er-status-progress {
  width: 100%;
  height: 6px;
  border: 0;
  border-radius: 999px;
}

.er-action-list {
  margin: 10px 0 0;
  padding-left: 1.3rem;
  line-height: 1.7;
}

.er-artifact {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
}

.er-method-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.er-method-card {
  min-width: 0;
  padding: 12px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: #fbfdff;
}

.er-empty { color: var(--er-muted); }

@media (max-width: 960px) {
  .er-shell { width: min(100% - 24px, 720px); }
  .er-hero,
  .er-two-col,
  .er-three-col,
  .er-method-grid {
    grid-template-columns: 1fr;
  }
  .er-meta-panel { border-left: 0; border-top: 1px solid var(--er-line); }
  .er-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 560px) {
  .er-shell { width: min(100% - 16px, 420px); padding-top: 12px; }
  .er-hero { padding: 18px; }
  .er-brand-mark { width: 52px; height: 52px; }
  .er-kpi-grid,
  .er-kpi-grid.compact,
  .er-two-mini {
    grid-template-columns: 1fr;
  }
  .er-bar-row { grid-template-columns: 1fr; }
  .er-section-nav { position: static; }
}

@media print {
  .er-section-nav,
  .er-button,
  .er-workspace-sidebar {
    display: none;
  }
  .er-app-layout.has-workspace-nav {
    display: block;
    width: auto;
  }
  .executive-report-page,
  .er-shell {
    background: white;
  }
  .er-section {
    break-before: page;
    page-break-before: always;
  }
}

/* Executive report v2 layout */
.executive-report-page {
  background: #f3f6fb;
  font-size: 15px;
}

.er-shell {
  width: min(1480px, calc(100vw - 32px));
  padding: 22px 0 48px;
}

.er-report-header {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(340px, 460px);
  gap: 24px;
  align-items: start;
  margin-bottom: 16px;
  padding: 4px 0 20px;
  border-bottom: 1px solid var(--er-line);
}

.er-compat-heading {
  display: none;
}

.er-report-header h1 {
  margin: 0;
  color: #07183d;
  font-size: clamp(2rem, 3vw, 2.75rem);
  line-height: 1.06;
  letter-spacing: 0;
}

.er-page-title {
  min-width: 0;
}

.er-report-intro {
  max-width: 760px;
  margin: 10px 0 0;
  color: #405373;
  font-size: 1rem;
  line-height: 1.45;
}

.er-report-intro strong {
  color: var(--er-text);
  font-weight: 850;
}

.er-report-meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 11px 16px;
  min-width: 0;
  padding: 14px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.82);
  box-shadow: 0 10px 24px rgba(7, 24, 61, 0.04);
  color: #405373;
}

.er-report-meta span {
  display: block;
  max-width: 100%;
  min-width: 0;
}

.er-report-meta em {
  display: block;
  color: var(--er-muted);
  font-size: 0.74rem;
  font-style: normal;
  font-weight: 850;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.er-report-meta strong {
  display: block;
  margin-top: 3px;
  overflow-wrap: anywhere;
  color: var(--er-text);
  font-size: 0.92rem;
  font-weight: 900;
}

.er-button {
  display: inline-flex;
  justify-content: center;
  align-items: center;
  min-height: 32px;
  margin-top: 2px;
  background: #ffffff;
}

.er-report-meta .er-button {
  grid-column: 1 / -1;
  width: 100%;
  margin-top: 0;
}

.er-section-nav {
  position: static;
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  margin: 0 0 14px;
  padding: 8px;
  overflow: visible;
  flex-wrap: wrap;
}

.er-section-nav a {
  flex: 0 0 auto;
  text-align: center;
  white-space: normal;
}

.er-section {
  margin-top: 14px;
  padding: 18px;
  box-shadow: 0 10px 28px rgba(7, 24, 61, 0.04);
}

.er-section-head {
  display: grid;
  grid-template-columns: minmax(220px, auto) minmax(0, 0.92fr);
  align-items: end;
}

.er-section-head > p {
  margin: 0;
  color: #405373;
  line-height: 1.45;
  text-align: right;
}

.er-section h2 {
  font-size: clamp(1.35rem, 2vw, 1.9rem);
}

.er-kpi-grid {
  grid-template-columns: repeat(4, minmax(150px, 1fr));
}

.er-kpi-grid.compact {
  grid-template-columns: repeat(4, minmax(150px, 1fr));
}

.er-kpi-grid.compact.er-action-kpis {
  grid-template-columns: repeat(5, minmax(150px, 1fr));
}

.er-overview-kpis {
  grid-template-columns: repeat(5, minmax(140px, 1fr));
}

.er-kpi {
  display: grid;
  min-height: 104px;
  align-content: center;
  padding: 14px 16px;
  border-color: #cfdbea;
  box-shadow: 0 8px 18px rgba(7, 24, 61, 0.04);
}

.er-kpi strong {
  margin: 7px 0;
  font-size: clamp(1.65rem, 2.4vw, 2.35rem);
}

.er-kpi.mini {
  min-height: 86px;
}

.er-overview-grid {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 14px;
  align-items: start;
}

.er-overview-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(310px, 0.46fr);
  gap: 14px;
  align-items: start;
}

.er-overview-main,
.er-overview-side {
  display: grid;
  gap: 14px;
}

.er-span-3 { grid-column: span 3; }
.er-span-6 { grid-column: span 6; }
.er-span-12 { grid-column: 1 / -1; }

.er-panel {
  padding: 16px;
  border-color: #cfdbea;
  box-shadow: 0 6px 18px rgba(7, 24, 61, 0.035);
}

.er-panel h3 {
  margin-bottom: 12px;
  font-size: 1.02rem;
  line-height: 1.22;
}

.er-panel h4 {
  font-size: 0.92rem;
}

.er-pipeline {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 8px;
  align-items: stretch;
}

.er-pipeline-step {
  position: relative;
  display: grid;
  gap: 6px;
  min-height: 118px;
  align-content: center;
  justify-items: center;
  padding: 12px 8px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #f8fbff;
  text-align: center;
}

.er-step-icon {
  display: grid;
  width: 38px;
  height: 38px;
  place-items: center;
  border-radius: 999px;
  background: #eaf2ff;
  color: var(--er-blue);
  font-weight: 900;
}

.er-pipeline-step small {
  color: var(--er-muted);
  line-height: 1.25;
}

.er-summary-list {
  display: grid;
  gap: 10px;
}

.er-summary-item {
  position: relative;
  padding: 10px 10px 10px 42px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-summary-item::before {
  content: "";
  position: absolute;
  top: 13px;
  left: 12px;
  width: 18px;
  height: 18px;
  border-radius: 999px;
  background: var(--er-blue);
}

.er-summary-item[data-tone="critical"]::before { background: var(--er-critical); }
.er-summary-item[data-tone="high"]::before { background: var(--er-high); }
.er-summary-item[data-tone="success"]::before { background: var(--er-success); }
.er-summary-item[data-tone="accent"]::before { background: var(--er-accent); }
.er-summary-item[data-tone="low"]::before { background: var(--er-low); }

.er-summary-item p {
  margin: 4px 0 0;
  color: #405373;
  line-height: 1.35;
}

.er-signal-card-row {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}

.er-signal-card {
  display: grid;
  gap: 8px;
  padding: 13px;
  border: 1px solid #cfdbea;
  border-radius: 8px;
  background: #ffffff;
}

.er-signal-card span {
  color: var(--er-muted);
  font-weight: 800;
}

.er-signal-card strong {
  color: var(--er-blue);
  font-size: 1.3rem;
}

.er-driver-row,
.er-ranked-row,
.er-remed-row {
  display: grid;
  gap: 9px;
  align-items: center;
}

.er-driver-row {
  grid-template-columns: auto minmax(110px, 1fr) minmax(90px, 1.4fr) auto;
}

.er-driver-dot {
  display: inline-block;
  width: 11px;
  height: 11px;
  border-radius: 999px;
  background: var(--er-blue);
}

.er-driver-dot[data-tone="critical"] { background: var(--er-critical); }
.er-driver-dot[data-tone="high"] { background: var(--er-high); }
.er-driver-dot[data-tone="medium"] { background: var(--er-medium); }
.er-driver-dot[data-tone="success"] { background: var(--er-success); }
.er-driver-dot[data-tone="accent"] { background: var(--er-accent); }
.er-driver-dot[data-tone="low"] { background: var(--er-low); }

.er-three-col {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: start;
}

.er-two-col {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: start;
}

.er-risk-chart-grid,
.er-evidence-core-grid {
  grid-template-columns: repeat(2, minmax(360px, 1fr));
}

.er-priority-analysis-grid {
  grid-template-columns: minmax(360px, 0.95fr) minmax(410px, 1.05fr) minmax(360px, 0.95fr);
}

.er-attack-summary-grid,
.er-remediation-grid {
  grid-template-columns: minmax(320px, 0.95fr) minmax(360px, 1fr) minmax(340px, 0.95fr);
}

.er-remediation-board {
  display: grid;
  grid-template-columns: minmax(0, 2.15fr) minmax(310px, 0.85fr);
  gap: 14px;
  align-items: start;
}

.er-remediation-main {
  display: grid;
  gap: 14px;
  min-width: 0;
}

.er-remediation-charts,
.er-action-detail-grid {
  margin-top: 0;
}

.er-action-detail-grid {
  grid-template-columns: 1fr;
}

.er-next-actions-panel {
  align-self: start;
}

.er-evidence-support-grid {
  grid-template-columns: minmax(280px, 0.85fr) minmax(320px, 0.95fr) minmax(420px, 1.2fr);
}

.er-evidence-lower-grid {
  grid-template-columns: 1fr;
  align-items: start;
}

.er-section-table {
  margin-top: 14px;
}

.er-table th {
  background: #f6f9fd;
  color: #23395f;
  font-size: 0.78rem;
  text-transform: uppercase;
}

.er-table td {
  color: #132646;
}

.er-table td:nth-child(2) strong {
  white-space: nowrap;
}

.er-table td:last-child {
  max-width: 440px;
}

.er-table-compact {
  min-width: 720px;
}

.er-bar-row {
  grid-template-columns: minmax(110px, 1fr) minmax(100px, 1.8fr) minmax(44px, auto);
}

.er-scatter {
  min-height: 190px;
  max-height: 220px;
}

.er-exposure-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.er-exposure-tile {
  display: grid;
  gap: 5px;
  min-height: 96px;
  align-content: center;
  padding: 12px;
  border-radius: 8px;
  background: linear-gradient(135deg, #dc2626, #f97316);
  color: #ffffff;
}

.er-exposure-tile[data-tone="high"] { background: linear-gradient(135deg, #f97316, #d99a07); }
.er-exposure-tile[data-tone="success"] { background: linear-gradient(135deg, #059669, #8bcf9c); }

.er-exposure-tile small {
  opacity: 0.86;
}

.er-ranked-list {
  display: grid;
  gap: 9px;
}

.er-ranked-row {
  grid-template-columns: 24px minmax(145px, 1.15fr) minmax(110px, 1.55fr) 38px;
  font-size: 0.88rem;
}

.er-ranked-row strong {
  white-space: nowrap;
}

.er-ranked-row > span {
  display: grid;
  height: 24px;
  place-items: center;
  border-radius: 999px;
  background: #eaf2ff;
  color: var(--er-blue);
  font-weight: 900;
}

.er-rank-progress {
  width: 100%;
  height: 10px;
  overflow: hidden;
  border: 0;
  border-radius: 999px;
  background: #edf2f8;
}

.er-rank-progress::-webkit-progress-bar {
  border-radius: inherit;
  background: #edf2f8;
}

.er-rank-progress::-webkit-progress-value {
  border-radius: inherit;
  background: var(--er-blue);
}

.er-rank-progress::-moz-progress-bar {
  border-radius: inherit;
  background: var(--er-blue);
}

.er-rank-progress[data-tone="critical"]::-webkit-progress-value { background: var(--er-critical); }
.er-rank-progress[data-tone="high"]::-webkit-progress-value { background: var(--er-high); }
.er-rank-progress[data-tone="medium"]::-webkit-progress-value { background: var(--er-medium); }

.er-ranked-row em,
.er-remed-row em,
.er-donut-legend-row em {
  color: var(--er-muted);
  font-style: normal;
  font-weight: 800;
}

.er-donut-wrap {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 14px;
  align-items: center;
}

.er-donut-svg {
  width: 150px;
  height: 150px;
}

.er-donut-bg {
  fill: none;
  stroke: #e8eef6;
  stroke-width: 18;
}

.er-donut-total {
  fill: var(--er-text);
  font-size: 1.45rem;
  font-weight: 900;
  text-anchor: middle;
}

.er-donut-caption {
  fill: var(--er-muted);
  font-size: 0.65rem;
  font-weight: 800;
  text-anchor: middle;
}

.er-donut-legend {
  display: grid;
  gap: 8px;
}

.er-donut-legend-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
}

.er-heatmap {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 6px;
}

.er-heat-cell {
  display: grid;
  min-height: 54px;
  align-content: center;
  padding: 8px;
  border-radius: 6px;
  background: #fde2e2;
  color: #07183d;
}

.er-heat-cell.er-heat-2 { background: #ffc9c9; }
.er-heat-cell.er-heat-3 { background: #ff9b9b; }
.er-heat-cell.er-heat-4 { background: #f87171; }

.er-heat-cell span {
  color: #405373;
}

.er-ttp-chain {
  display: flex;
  flex-wrap: wrap;
  gap: 22px;
  align-items: center;
}

.er-ttp-chain span {
  position: relative;
  display: inline-flex;
  min-height: 42px;
  align-items: center;
  padding: 0 12px;
  border-radius: 999px;
  background: #eaf2ff;
  color: var(--er-blue);
  font-weight: 900;
}

.er-ttp-chain span:not(:last-child)::after {
  content: ">";
  position: absolute;
  right: -16px;
  color: #7d8da6;
}

.er-remed-chart {
  display: grid;
  gap: 12px;
}

.er-remed-row {
  grid-template-columns: 68px minmax(130px, 1fr) 34px;
}

.er-remed-bars {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

.er-remed-bars span {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.er-remed-bars b {
  color: var(--er-muted);
  font-size: 0.68rem;
}

.er-remed-bars progress {
  width: 100%;
  height: 8px;
  border: 0;
  border-radius: 999px;
}

.er-remed-bars progress::-webkit-progress-bar {
  border-radius: inherit;
  background: #edf2f8;
}

.er-remed-bars progress::-webkit-progress-value {
  border-radius: inherit;
  background: var(--er-blue);
}

.er-remed-bars progress[data-tone="critical"]::-webkit-progress-value {
  background: var(--er-critical);
}

.er-remed-bars progress[data-tone="low"]::-webkit-progress-value {
  background: var(--er-low);
}

.er-remed-bars progress[data-tone="medium"]::-webkit-progress-value {
  background: var(--er-medium);
}

.er-pipeline-panel {
  margin-bottom: 14px;
}

.er-coverage-context-panel {
  margin-bottom: 14px;
}

.er-coverage-context-panel .er-signal-card-row {
  margin: 12px 0 0;
}

.er-priority-subhead {
  margin-top: 16px;
  padding: 4px 0;
}

.er-priority-subhead h3 {
  margin: 0;
  font-size: 1.05rem;
}

.er-dossier-list {
  display: grid;
  gap: 12px;
  margin-top: 12px;
}

.er-dossier-card {
  display: grid;
  gap: 14px;
  padding: 14px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
}

.er-dossier-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(180px, 0.32fr);
  gap: 14px;
  align-items: start;
}

.er-dossier-head h4 {
  margin: 8px 0 4px;
  color: var(--er-blue);
  font-size: 1.15rem;
}

.er-dossier-head p,
.er-dossier-details p {
  margin: 0;
  color: #405373;
  line-height: 1.45;
}

.er-dossier-score {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 6px 10px;
  margin: 0;
  padding: 10px;
  border-radius: 8px;
  background: #ffffff;
}

.er-dossier-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.er-detail-list.compact {
  grid-template-columns: minmax(90px, 0.7fr) minmax(0, 1fr);
  font-size: 0.82rem;
}

.er-dossier-details {
  border-top: 1px solid #d7e3f3;
  padding-top: 10px;
}

.er-dossier-details summary {
  cursor: pointer;
  color: var(--er-blue);
  font-weight: 850;
}

.er-dossier-details[open] {
  display: grid;
  gap: 8px;
}

.er-input-table {
  min-width: min(620px, 100%);
}

.er-provider-transparency,
.er-command-list,
.er-governance-grid,
.er-missing-context {
  display: grid;
  gap: 10px;
}

.er-command-list code {
  display: block;
  padding: 8px 10px;
  border: 1px solid #d7e3f3;
  border-radius: 7px;
  background: #f6f9fd;
  color: #132646;
  font-size: 0.8rem;
  overflow-wrap: anywhere;
}

.er-governance-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.er-governance-item {
  padding: 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-governance-item strong {
  display: block;
  color: var(--er-blue);
  font-size: 1.45rem;
}

.er-governance-item[data-tone="critical"] strong { color: var(--er-critical); }
.er-governance-item[data-tone="high"] strong { color: var(--er-high); }
.er-governance-item[data-tone="medium"] strong { color: var(--er-medium); }
.er-governance-item[data-tone="low"] strong { color: var(--er-low); }

.er-governance-item span {
  font-weight: 850;
}

.er-governance-item p {
  margin: 5px 0 0;
  color: #405373;
  font-size: 0.84rem;
}

.er-missing-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 6px 12px;
  padding: 10px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-missing-item p {
  margin: 3px 0 0;
  color: #405373;
  font-size: 0.83rem;
}

.er-missing-item > span {
  color: var(--er-blue);
  font-weight: 900;
}

.er-missing-item .er-progress {
  grid-column: 1 / -1;
}

.er-flow-map {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(110px, 0.55fr) minmax(0, 1fr);
  gap: 12px;
  align-items: stretch;
}

.er-flow-source,
.er-flow-engine,
.er-flow-output {
  position: relative;
  display: grid;
  min-width: 0;
  min-height: 112px;
  align-content: start;
  gap: 8px;
  padding: 14px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
}

.er-flow-engine {
  justify-items: center;
  align-content: center;
  background: #eaf2ff;
  color: var(--er-blue);
  text-align: center;
}

.er-flow-source::after,
.er-flow-engine::after {
  content: "";
  position: absolute;
  top: 50%;
  right: -13px;
  width: 13px;
  border-top: 2px solid #b8c7da;
}

.er-flow-source strong,
.er-flow-engine strong,
.er-flow-output strong,
.er-provider-card strong,
.er-focus-card strong,
.er-quality-matrix strong {
  overflow-wrap: anywhere;
}

.er-flow-source span,
.er-flow-output span,
.er-provider-card span,
.er-threshold-legend span,
.er-evidence-file-list span {
  color: var(--er-muted);
  font-size: 0.8rem;
  font-weight: 800;
}

.er-quadrant-scatter,
.er-stacked-chart,
.er-waterfall {
  display: block;
  width: 100%;
  max-width: 100%;
  min-height: 220px;
  overflow: visible;
}

.er-quadrant-scatter {
  color: var(--er-muted);
  font-size: 0.72rem;
}

.er-stacked-chart,
.er-waterfall {
  color: #405373;
}

.er-provider-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.er-provider-signal-panel .er-provider-cards {
  grid-template-columns: repeat(3, minmax(240px, 1fr));
}

.er-focus-card-grid {
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

.er-provider-card,
.er-focus-card {
  display: grid;
  min-width: 0;
  gap: 8px;
  padding: 13px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-provider-card p {
  margin: 0;
  color: #405373;
  font-size: 0.86rem;
  line-height: 1.4;
}

.er-provider-card {
  border-top: 4px solid var(--er-blue);
  min-height: 0;
}

.er-provider-card[data-tone="critical"],
.er-focus-card[data-tone="critical"] {
  border-color: #fecaca;
  border-top-color: var(--er-critical);
  background: #fff7f7;
}

.er-provider-card[data-tone="high"],
.er-focus-card[data-tone="high"] {
  border-color: #fed7aa;
  border-top-color: var(--er-high);
  background: #fff9f2;
}

.er-provider-card[data-tone="medium"],
.er-focus-card[data-tone="medium"] {
  border-color: #fde68a;
  border-top-color: var(--er-medium);
  background: #fffdf2;
}

.er-provider-card[data-tone="success"],
.er-focus-card[data-tone="success"] {
  border-color: #bbf7d0;
  border-top-color: var(--er-success);
  background: #f3fcf7;
}

.er-threshold-legend,
.er-technique-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.er-threshold-legend span,
.er-technique-strip span {
  display: inline-flex;
  min-width: 0;
  min-height: 28px;
  align-items: center;
  gap: 7px;
  padding: 0 10px;
  border: 1px solid #d7e3f3;
  border-radius: 999px;
  background: #f8fbff;
  color: #25405f;
  overflow-wrap: anywhere;
}

.er-threshold-legend span::before,
.er-technique-strip span::before {
  content: "";
  width: 9px;
  height: 9px;
  flex: 0 0 auto;
  border-radius: 999px;
  background: var(--er-blue);
}

.er-threshold-legend span[data-tone="critical"]::before,
.er-technique-strip span[data-tone="critical"]::before { background: var(--er-critical); }
.er-threshold-legend span[data-tone="high"]::before,
.er-technique-strip span[data-tone="high"]::before { background: var(--er-high); }
.er-threshold-legend span[data-tone="medium"]::before,
.er-technique-strip span[data-tone="medium"]::before { background: var(--er-medium); }
.er-threshold-legend span[data-tone="success"]::before,
.er-technique-strip span[data-tone="success"]::before { background: var(--er-success); }
.er-threshold-legend span[data-tone="low"]::before,
.er-technique-strip span[data-tone="low"]::before { background: var(--er-low); }

.er-interpretation-panel {
  display: grid;
  gap: 10px;
  padding: 14px;
  border: 1px solid #cfdbea;
  border-left: 4px solid var(--er-blue);
  border-radius: 8px;
  background: #f8fbff;
}

.er-interpretation-panel p {
  margin: 0;
  color: #405373;
  line-height: 1.45;
}

.er-next-steps {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.er-next-steps-vertical {
  grid-template-columns: 1fr;
}

.er-next-steps li {
  display: grid;
  min-width: 0;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-next-steps li::before {
  display: none;
}

.er-next-steps span {
  color: #405373;
  font-size: 0.82rem;
  line-height: 1.4;
}

.er-focus-card {
  border-left: 4px solid var(--er-blue);
}

.er-focus-card p {
  margin: 0;
  color: #405373;
  line-height: 1.42;
}

.er-focus-card ul {
  display: grid;
  gap: 5px;
  margin: 0;
  padding-left: 18px;
  color: #405373;
  font-size: 0.82rem;
}

.er-empty-state {
  display: grid;
  align-content: center;
  gap: 8px;
  min-height: 220px;
  padding: 16px;
  border: 1px dashed #cfdbea;
  border-radius: 8px;
  background: #f8fbff;
  color: #405373;
}

.er-empty-state strong {
  color: var(--er-blue);
  font-size: 1.1rem;
}

.er-empty-state p {
  margin: 0;
}

.er-confidence-layout {
  display: grid;
  grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
  gap: 14px;
  align-items: start;
}

.er-attack-matrix {
  grid-template-columns: minmax(120px, 1fr) repeat(3, minmax(80px, 1fr));
}

.er-heat-head,
.er-heat-label {
  min-width: 0;
  padding: 7px 8px;
  color: #405373;
  font-size: 0.78rem;
  font-weight: 900;
  overflow-wrap: anywhere;
}

.er-heat-head {
  background: #eef5ff;
}

.er-heat-label {
  background: #ffffff;
}

.er-evidence-file-list {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.er-evidence-file-list li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px 12px;
  align-items: center;
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid #d7e3f3;
  border-radius: 7px;
  background: #ffffff;
}

.er-evidence-file-list code {
  min-width: 0;
  color: #132646;
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}

.er-quality-matrix {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.er-quality-matrix > * {
  display: grid;
  min-width: 0;
  min-height: 76px;
  align-content: center;
  gap: 4px;
  padding: 10px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-quality-matrix strong {
  color: var(--er-blue);
  font-size: 1.2rem;
}

.er-quality-matrix span {
  color: var(--er-muted);
  font-size: 0.76rem;
  font-weight: 800;
}

.er-evidence-core-grid .er-table-compact {
  min-width: 620px;
}

.er-quality-matrix + .er-warning-list {
  margin-top: 12px;
}

.er-method-grid.compact {
  grid-template-columns: repeat(2, minmax(210px, 1fr));
}

.er-warning-list p {
  margin: 0;
  padding: 9px 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
  color: #23395f;
  line-height: 1.4;
}

.er-provider-transparency {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: start;
}

.er-provider-transparency > .er-detail-list {
  grid-column: 1 / -1;
  padding: 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
}

.er-provider-transparency > div {
  min-width: 0;
  padding: 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-provider-transparency .er-eyebrow {
  margin-bottom: 8px;
}

.er-section-nav a.is-active {
  background: #eaf2ff;
  color: var(--er-blue);
  box-shadow: inset 0 -2px 0 var(--er-blue);
}

.er-interactive-target {
  cursor: pointer;
  transition:
    border-color 160ms ease,
    box-shadow 160ms ease,
    transform 160ms ease,
    background-color 160ms ease,
    opacity 160ms ease;
}

.er-provider-card.er-interactive-target:hover,
.er-signal-card.er-interactive-target:hover,
.er-quality-matrix > article.er-interactive-target:hover,
.er-summary-item.er-interactive-target:hover,
.er-ranked-row.er-interactive-target:hover,
.er-bar-row.er-interactive-target:hover,
.er-driver-row.er-interactive-target:hover,
.er-remed-row.er-interactive-target:hover,
.er-heat-cell.er-interactive-target:hover,
.er-donut-legend-row.er-interactive-target:hover,
.er-focus-card.er-interactive-target:hover,
.er-method-card.er-interactive-target:hover,
.er-pipeline-step.er-interactive-target:hover,
.er-evidence-file-list li.er-interactive-target:hover,
.er-exposure-tile.er-interactive-target:hover,
.er-status-segment.er-interactive-target:hover {
  border-color: #94bfff;
  box-shadow: 0 12px 26px rgba(11, 99, 246, 0.13);
  transform: translateY(-2px);
}

.er-interactive-target:focus-visible {
  outline: 3px solid rgba(11, 99, 246, 0.28);
  outline-offset: 3px;
}

.er-stacked-chart rect.er-interactive-target,
.er-quadrant-scatter .er-dot,
.er-donut-segment {
  transform-box: fill-box;
  transform-origin: center;
  transition:
    filter 160ms ease,
    opacity 160ms ease,
    stroke-width 160ms ease,
    transform 160ms ease;
}

.er-stacked-chart rect.er-interactive-target:hover,
.er-stacked-chart rect.er-interactive-target:focus-visible,
.er-quadrant-scatter .er-dot:hover,
.er-quadrant-scatter .er-dot:focus-visible,
.er-donut-segment:hover,
.er-donut-segment:focus-visible {
  filter: drop-shadow(0 5px 8px rgba(7, 24, 61, 0.28));
  opacity: 0.92;
  transform: scale(1.08);
}

.er-donut-segment:hover,
.er-donut-segment:focus-visible {
  stroke-width: 21;
}

.er-live-insight {
  display: grid;
  grid-template-columns: minmax(120px, auto) minmax(0, 1fr);
  gap: 4px 12px;
  align-items: center;
  margin: -2px 0 14px;
  padding: 10px 12px;
  border: 1px solid #bfdbfe;
  border-left: 4px solid var(--er-blue);
  border-radius: 8px;
  background: linear-gradient(90deg, #eff6ff, #ffffff);
}

.er-live-insight[hidden] {
  display: none;
}

.er-live-insight span {
  color: var(--er-muted);
  font-size: 0.72rem;
  font-weight: 900;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.er-live-insight strong {
  min-width: 0;
  color: var(--er-blue);
  overflow-wrap: anywhere;
}

.er-live-insight p {
  grid-column: 2;
  margin: 0;
  color: #405373;
  font-size: 0.82rem;
}

.er-floating-tip {
  position: fixed;
  z-index: 1000;
  display: none;
  max-width: min(320px, calc(100vw - 24px));
  padding: 9px 11px;
  border: 1px solid #bfdbfe;
  border-radius: 8px;
  background: rgba(7, 24, 61, 0.96);
  box-shadow: 0 18px 40px rgba(7, 24, 61, 0.22);
  color: #ffffff;
  font-size: 0.82rem;
  font-weight: 760;
  line-height: 1.35;
  pointer-events: none;
}

.er-floating-tip.is-visible {
  display: block;
}

.is-selected {
  border-color: #0b63f6 !important;
  box-shadow: 0 0 0 2px rgba(11, 99, 246, 0.18), 0 12px 26px rgba(11, 99, 246, 0.12);
}

.er-cve-spotlight {
  outline: 2px solid rgba(249, 115, 22, 0.55);
  outline-offset: 2px;
}

.er-table tr.er-cve-spotlight td {
  background: #fff7ed;
}

@media (prefers-reduced-motion: reduce) {
  .er-interactive-target,
  .er-stacked-chart rect.er-interactive-target,
  .er-quadrant-scatter .er-dot,
  .er-donut-segment {
    transition: none;
  }
}

@media (max-width: 1120px) {
  .er-app-header {
    position: static;
    min-height: 60px;
    padding: 0 16px;
  }
  .er-app-layout.has-workspace-nav {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .sidebar-collapsed .er-app-layout.has-workspace-nav {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .er-workspace-sidebar {
    position: static;
    max-height: none;
    padding: 16px 0 14px;
  }
  .sidebar-collapsed .er-workspace-sidebar {
    padding: 16px 0 14px;
  }
  .sidebar-collapsed .sidebar-toggle {
    justify-content: flex-start;
    padding: 0 10px;
  }
  .sidebar-collapsed .sidebar-toggle-text,
  .sidebar-collapsed .nav-label,
  .sidebar-collapsed .project-copy {
    position: static;
    width: auto;
    height: auto;
    overflow: visible;
    clip: auto;
    clip-path: none;
    white-space: normal;
  }
  .sidebar-collapsed .sidebar-toggle-icon::before,
  .sidebar-collapsed .sidebar-toggle-icon::after {
    transform: rotate(135deg);
  }
  .sidebar-collapsed .er-workspace-project {
    justify-content: flex-start;
    padding: 12px;
  }
  .er-workspace-nav {
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }
  .sidebar-collapsed .er-workspace-nav-group a {
    justify-content: flex-start;
    min-height: 39px;
    padding: 0 10px;
  }
  .sidebar-collapsed .er-workspace-nav-group p {
    height: auto;
    margin: 0 0 4px;
    padding: 0 10px;
    overflow: visible;
    background: transparent;
    color: var(--er-muted);
  }
  .er-report-header {
    grid-template-columns: 1fr;
  }
  .er-report-meta {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    width: 100%;
  }
  .er-kpi-grid,
  .er-kpi-grid.compact,
  .er-signal-card-row {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .er-kpi-grid.compact.er-action-kpis {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .er-overview-grid {
    grid-template-columns: repeat(6, minmax(0, 1fr));
  }
  .er-overview-layout {
    grid-template-columns: 1fr;
  }
  .er-span-3,
  .er-span-6 {
    grid-column: span 3;
  }
  .er-span-12 {
    grid-column: 1 / -1;
  }
  .er-pipeline {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .er-provider-cards,
  .er-next-steps {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-risk-chart-grid,
  .er-priority-analysis-grid,
  .er-attack-summary-grid,
  .er-remediation-grid,
  .er-evidence-core-grid,
  .er-evidence-support-grid,
  .er-evidence-lower-grid {
    grid-template-columns: 1fr;
  }
  .er-remediation-board,
  .er-remediation-charts,
  .er-action-detail-grid {
    grid-template-columns: 1fr;
  }
  .er-provider-signal-panel .er-provider-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-confidence-layout {
    grid-template-columns: 1fr;
  }
  .er-provider-transparency {
    grid-template-columns: 1fr;
  }
  .er-quality-matrix {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-three-col {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 760px) {
  .er-app-layout {
    width: min(100% - 20px, 760px);
  }
  .er-workspace-nav {
    grid-template-columns: 1fr 1fr;
  }
  .er-shell {
    width: min(100% - 20px, 760px);
    padding-top: 12px;
  }
  .er-report-header {
    gap: 14px;
    padding-bottom: 12px;
  }
  .er-report-header h1 {
    font-size: clamp(1.8rem, 8vw, 2.35rem);
  }
  .er-report-intro {
    font-size: 0.94rem;
  }
  .er-report-meta,
  .er-kpi-grid,
  .er-kpi-grid.compact,
  .er-signal-card-row,
  .er-flow-map,
  .er-provider-cards,
  .er-next-steps,
  .er-two-col,
  .er-risk-chart-grid,
  .er-priority-analysis-grid,
  .er-attack-summary-grid,
  .er-remediation-grid,
  .er-remediation-board,
  .er-remediation-charts,
  .er-action-detail-grid,
  .er-evidence-core-grid,
  .er-evidence-support-grid,
  .er-evidence-lower-grid,
  .er-dossier-head,
  .er-dossier-grid,
  .er-governance-grid,
  .er-method-grid,
  .er-pipeline,
  .er-exposure-grid {
    grid-template-columns: 1fr;
  }
  .er-section-head {
    grid-template-columns: 1fr;
  }
  .er-section-head > p {
    text-align: left;
  }
  .er-flow-source,
  .er-flow-engine,
  .er-flow-output {
    min-height: 0;
  }
  .er-flow-source::after,
  .er-flow-engine::after {
    top: auto;
    right: 50%;
    bottom: -13px;
    width: 0;
    height: 13px;
    border-top: 0;
    border-left: 2px solid #b8c7da;
  }
  .er-overview-grid {
    grid-template-columns: 1fr;
  }
  .er-overview-layout {
    grid-template-columns: 1fr;
  }
  .er-span-3,
  .er-span-6,
  .er-span-12 {
    grid-column: 1 / -1;
  }
  .er-donut-wrap {
    grid-template-columns: 1fr;
    justify-items: center;
  }
  .er-driver-row,
  .er-bar-row {
    grid-template-columns: auto minmax(0, 1fr) auto;
  }
  .er-driver-row .er-progress {
    grid-column: 2 / -1;
  }
  .er-heatmap {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-evidence-file-list li,
  .er-quality-matrix,
  .er-method-grid.compact,
  .er-provider-transparency,
  .er-live-insight {
    grid-template-columns: 1fr;
  }
  .er-live-insight p {
    grid-column: 1;
  }
  .er-section-nav {
    display: grid;
    grid-template-columns: 1fr;
    overflow-x: visible;
  }
  .er-section-nav a {
    white-space: normal;
  }
  .er-table,
  .er-table-compact,
  .er-input-table {
    min-width: 680px;
    table-layout: auto;
  }
  .er-table th,
  .er-table td {
    padding: 8px;
    font-size: 0.78rem;
  }
  .er-table td:last-child {
    max-width: none;
  }
}

"""
