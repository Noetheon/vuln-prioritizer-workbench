"""Executive HTML report stylesheet."""

from __future__ import annotations

EXECUTIVE_REPORT_CSS = """
:root {
  color-scheme: light;
  --vpw-bg-app: #fafafa; --vpw-bg-card: #ffffff; --vpw-bg-panel: #f5f5f5;
  --vpw-bg-info: #eef6ff; --vpw-bg-warning: #fff7e6; --vpw-bg-critical: #fff1f1;
  --vpw-text-primary: #171717; --vpw-text-secondary: #4d4d4d; --vpw-text-muted: #6b6b6b;
  --vpw-border-default: #ebebeb; --vpw-blue: #0070f3; --vpw-teal: #047857;
  --vpw-green: #047857; --vpw-amber: #b54708; --vpw-red: #c40000; --vpw-violet: #475569;
  --vpw-radius-lg: 8px; --vpw-radius-xl: 8px; --medium: #d97706; --low: #0ea5e9;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--vpw-bg-app); color: var(--vpw-text-primary);
  font-family: "Geist", "Aptos", ui-sans-serif, system-ui, -apple-system,
    BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px; line-height: 1.5; text-rendering: optimizeLegibility;
}
.report-shell { width: min(1280px, calc(100% - 32px)); margin: 0 auto; padding: 24px 0 40px; }
header, section {
  margin-bottom: 16px; border: 1px solid var(--vpw-border-default);
  border-radius: var(--vpw-radius-xl);
  background: var(--vpw-bg-card); padding: 20px; box-shadow: none;
}
h1, h2, h3, p { margin-top: 0; }
h1 {
  margin-bottom: 8px; color: var(--vpw-text-primary); font-size: 30px;
  font-weight: 720; line-height: 1.15; letter-spacing: 0;
}
h2 {
  margin-bottom: 10px; color: var(--vpw-text-primary); font-size: 20px;
  font-weight: 720; line-height: 1.25; letter-spacing: 0;
}
h3 {
  margin: 22px 0 10px; color: var(--vpw-text-primary); font-size: 15px;
  font-weight: 650; line-height: 1.3; letter-spacing: 0;
}
.eyebrow, dt, .metric span, th {
  font-family: "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular,
    Menlo, Monaco, Consolas, monospace;
  font-size: 12px; line-height: 1rem; letter-spacing: 0; text-transform: uppercase;
}
.eyebrow { margin-bottom: 6px; color: var(--vpw-teal); font-weight: 600; }
.lede {
  max-width: 56rem; color: var(--vpw-text-secondary); font-size: 14px; line-height: 1.5;
}
.section-heading { margin-bottom: 12px; }
.meta-grid, .metric-grid, .provider-grid {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px;
}
.meta-grid { margin: 18px 0 0; }
.metric-grid { margin-bottom: 14px; }
.meta-grid div, .metric, .provider-grid div {
  min-width: 0; border: 1px solid var(--vpw-border-default); border-radius: var(--vpw-radius-lg);
  background: var(--vpw-bg-card); padding: 12px;
}
.meta-grid div, .provider-grid div { background: var(--vpw-bg-panel); }
.metric { min-height: 78px; align-content: center; box-shadow: inset 2px 0 0 var(--vpw-violet); }
.metric[data-tone="info"] { box-shadow: inset 2px 0 0 var(--vpw-blue); }
.metric[data-tone="success"] { box-shadow: inset 2px 0 0 var(--vpw-green); }
.metric[data-tone="warning"] { box-shadow: inset 2px 0 0 var(--vpw-amber); }
.metric[data-tone="critical"] { box-shadow: inset 2px 0 0 var(--vpw-red); }
dt, .metric span { color: var(--vpw-text-muted); font-weight: 500; }
dd { margin: 4px 0 0; color: var(--vpw-text-primary); overflow-wrap: anywhere; }
.metric strong {
  display: block; margin-top: 4px; color: var(--vpw-text-primary);
  font-size: 24px; font-weight: 720; line-height: 1.1; letter-spacing: 0;
}
.table-wrap {
  overflow-x: auto; border: 1px solid var(--vpw-border-default);
  border-radius: var(--vpw-radius-lg);
}
table {
  width: 100%; min-width: 960px; border-collapse: collapse; background: var(--vpw-bg-card);
}
th, td {
  border-bottom: 1px solid var(--vpw-border-default); padding: 10px 8px;
  text-align: left; vertical-align: top;
}
th { color: var(--vpw-text-muted); background: var(--vpw-bg-panel); font-weight: 500; }
td { color: var(--vpw-text-primary); font-size: 14px; overflow-wrap: anywhere; }
tbody tr:last-child td { border-bottom: 0; }
.badge {
  display: inline-flex; align-items: center; border: 1px solid transparent; border-radius: 9999px;
  background: var(--vpw-bg-info); color: var(--vpw-blue); padding: 2px 8px;
  font-size: 12px; font-weight: 600; line-height: 1.25; white-space: nowrap;
}
tbody td:nth-child(-n + 7), thead th:nth-child(-n + 7) { white-space: nowrap; }
.badge-critical {
  border-color: #fecaca; background: var(--vpw-bg-critical); color: var(--vpw-red);
}
.badge-high { border-color: #fed7aa; background: var(--vpw-bg-warning); color: var(--vpw-amber); }
.badge-medium { border-color: #fde68a; background: #fffbeb; color: var(--medium); }
.badge-low { border-color: #bae6fd; background: #f0f9ff; color: var(--low); }
.badge-overdue { border-color: #fecaca; background: #fff1f1; color: var(--vpw-red); }
.badge-fresh { border-color: #a7f3d0; background: #ecfdf5; color: #047857; }
.badge-warning-alt { border-color: #fed7aa; background: #fff7e6; color: #b54708; }
.badge-stale { border-color: #fca5a5; background: #fff1f1; color: #c40000; }
.badge-success { border-color: #a7f3d0; background: #ecfdf5; color: #047857; }

.verdict-banner {
  background: var(--vpw-bg-panel);
  border: 1px solid var(--vpw-border-default);
  border-radius: var(--vpw-radius-lg);
  padding: 16px;
  margin-bottom: 18px;
}
.verdict-banner p { margin-bottom: 8px; }
.verdict-banner p:last-child { margin-bottom: 0; }

.campaign-card {
  border: 1px solid var(--vpw-border-default);
  border-radius: var(--vpw-radius-lg);
  background: var(--vpw-bg-card);
  padding: 16px;
  margin-bottom: 16px;
}
.campaign-card:last-child { margin-bottom: 0; }
.campaign-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--vpw-border-default);
  padding-bottom: 10px;
  margin-bottom: 12px;
}
.campaign-title-group {
  display: flex;
  align-items: center;
  gap: 10px;
}
.campaign-title {
  font-size: 16px;
  font-weight: 720;
  margin: 0;
}
.campaign-meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 14px;
  background: var(--vpw-bg-panel);
  padding: 12px;
  border-radius: var(--vpw-radius-lg);
}
.campaign-meta-item {
  font-size: 13px;
  line-height: 1.4;
}
.campaign-meta-item strong {
  display: block;
  color: var(--vpw-text-secondary);
  font-weight: 650;
}
.campaign-assets-toggle {
  margin-top: 10px;
}
.campaign-assets-toggle summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--vpw-blue);
  outline: none;
  user-select: none;
}
.campaign-assets-table-wrap {
  margin-top: 8px;
  overflow-x: auto;
  border: 1px solid var(--vpw-border-default);
  border-radius: var(--vpw-radius-lg);
}
.campaign-assets-table-wrap table {
  min-width: 100%;
}
.campaign-assets-table-wrap th, .campaign-assets-table-wrap td {
  padding: 8px 10px;
  font-size: 13px;
}

.recommendation-list { margin: 0; padding-left: 22px; }
.recommendation-list li + li { margin-top: 12px; }
.recommendation-list strong { display: block; color: var(--vpw-text-primary); font-weight: 650; }
.recommendation-list span { color: var(--vpw-text-secondary); }
.empty-state { color: var(--vpw-text-muted); }
.text-muted { color: var(--vpw-text-muted); }
.signal-badge-row { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
.compact-table { min-width: 0; }
@media (max-width: 820px) {
  .report-shell { width: min(100% - 20px, 1280px); padding-top: 16px; }
  header, section { padding: 16px; }
  h1 { font-size: 26px; }
  .meta-grid, .metric-grid, .provider-grid { grid-template-columns: 1fr; }
  .campaign-header { align-items: flex-start; flex-direction: column; gap: 10px; }
  .signal-badge-row { justify-content: flex-start; }
}
@media print {
  body { background: #ffffff; color: #000000; }
  .report-shell { width: 100%; padding: 0; }
  header, section {
    border-color: #c8c8c8; break-inside: avoid; page-break-inside: avoid; padding: 18px;
  }
  .table-wrap { overflow: visible; }
  table { min-width: 0; }
}
""".strip()

__all__ = ["EXECUTIVE_REPORT_CSS"]
