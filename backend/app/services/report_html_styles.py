"""Executive HTML report stylesheet."""

from __future__ import annotations

EXECUTIVE_REPORT_CSS = """
:root {
  color-scheme: light;
  --bg-app: #fafafa;
  --bg-card: #ffffff;
  --bg-panel: #f5f5f5;
  --bg-info: #eef6ff;
  --bg-warning: #fff7e6;
  --bg-critical: #fff1f1;
  --bg-success: #ecfdf5;
  --text-primary: #171717;
  --text-secondary: #404040;
  --text-muted: #6b6b6b;
  --border: #e8e8e8;
  --blue: #006adc;
  --green: #047857;
  --amber: #b54708;
  --red: #c40000;
  --violet: #475569;
  --radius: 12px;
  --radius-sm: 8px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg-app);
  color: var(--text-primary);
  font-family:
    "Geist", "Aptos", Inter, ui-sans-serif, system-ui, -apple-system,
    BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  text-rendering: optimizeLegibility;
}
.report-shell {
  width: min(1280px, calc(100% - 32px));
  margin: 0 auto;
  padding: 24px 0 40px;
}
header, section {
  margin-bottom: 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg-card);
  padding: 20px;
}
h1, h2, h3, p { margin-top: 0; }
h1 {
  margin-bottom: 8px;
  font-size: 30px;
  line-height: 1.15;
  letter-spacing: 0;
  font-weight: 760;
}
h2 {
  margin-bottom: 8px;
  font-size: 20px;
  line-height: 1.25;
  letter-spacing: 0;
  font-weight: 740;
}
h3 {
  margin: 22px 0 10px;
  font-size: 15px;
  line-height: 1.3;
  font-weight: 680;
}
.eyebrow, dt, .metric span, th, .status-label {
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
  font-size: 12px;
  line-height: 1rem;
  letter-spacing: 0;
  text-transform: uppercase;
}
.eyebrow { margin-bottom: 6px; color: var(--green); font-weight: 650; }
.lede {
  max-width: none;
  width: 100%;
  color: var(--text-secondary);
}
.business-impact-lede {
  max-width: none;
  width: 100%;
}
.meta-grid, .metric-grid, .provider-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.meta-grid { margin-top: 18px; }
.meta-grid div, .metric, .provider-grid div {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px;
}
.meta-grid div, .provider-grid div { background: var(--bg-panel); }
dt, .metric span { color: var(--text-muted); font-weight: 560; }
dd { margin: 4px 0 0; overflow-wrap: anywhere; }
.metric {
  background: var(--bg-card);
  min-height: 80px;
  align-content: center;
  box-shadow: inset 3px 0 0 var(--violet);
}
.metric strong {
  display: block;
  margin-top: 4px;
  font-size: 25px;
  line-height: 1.05;
  font-weight: 760;
}
.metric[data-tone="critical"] { box-shadow: inset 3px 0 0 var(--red); }
.metric[data-tone="warning"] { box-shadow: inset 3px 0 0 var(--amber); }
.metric[data-tone="success"] { box-shadow: inset 3px 0 0 var(--green); }
.metric[data-tone="info"] { box-shadow: inset 3px 0 0 var(--blue); }
.verdict-banner {
  border: 1px solid #fed7aa;
  border-radius: var(--radius-sm);
  background: linear-gradient(180deg, #fff7e6 0%, #fffaf0 100%);
  padding: 16px;
  margin: 0 0 14px;
}
.verdict-banner strong { color: #7c2d12; }
.decision-grid {
  display: grid;
  grid-template-columns: 1.2fr 1fr;
  gap: 12px;
}
.decision-grid--three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.decision-card {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-card);
  padding: 14px;
}
.decision-card ul { margin: 8px 0 0 18px; padding: 0; }
.decision-card li + li { margin-top: 4px; }
.signoff-panel { margin-top: 12px; border: 1px solid var(--border);
  border-radius: var(--radius-sm); background: var(--bg-panel); padding: 14px; }
.signoff-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px; margin: 10px 0 0; }
.signoff-grid div {
  min-height: 54px; border: 1px solid var(--border); border-radius: var(--radius-sm);
  background: var(--bg-card); padding: 10px;
}
.signoff-grid dd:empty::after { content: ""; display: block; min-height: 18px;
  border-bottom: 1px solid #a3a3a3; }
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
}
table {
  width: 100%;
  min-width: 960px;
  border-collapse: collapse;
  background: var(--bg-card);
}
.compact-table { min-width: 0; }
th, td {
  border-bottom: 1px solid var(--border);
  padding: 10px 8px;
  text-align: left;
  vertical-align: top;
}
th { color: var(--text-muted); background: var(--bg-panel); font-weight: 560; }
td { color: var(--text-primary); overflow-wrap: anywhere; }
tbody tr:last-child td { border-bottom: 0; }
.badge {
  display: inline-flex;
  align-items: center;
  border: 1px solid transparent;
  border-radius: 9999px;
  padding: 2px 8px;
  font-size: 12px;
  font-weight: 680;
  line-height: 1.25;
  white-space: nowrap;
}
.badge-critical { border-color: #fecaca; background: var(--bg-critical); color: var(--red); }
.badge-high { border-color: #fed7aa; background: var(--bg-warning); color: var(--amber); }
.badge-info { border-color: #bfdbfe; background: var(--bg-info); color: var(--blue); }
.badge-success { border-color: #a7f3d0; background: var(--bg-success); color: var(--green); }
.badge-neutral { border-color: #d4d4d4; background: #f7f7f7; color: #525252; }
.badge-stale { border-color: #fecaca; background: var(--bg-critical); color: var(--red); }
.badge-warning { border-color: #fed7aa; background: var(--bg-warning); color: var(--amber); }
.signal-row { display: flex; flex-wrap: wrap; gap: 6px; }
.campaign-table td:nth-child(1),
.campaign-table td:nth-child(3),
.campaign-table td:nth-child(4) {
  white-space: nowrap;
}
.evidence-package-table code {
  white-space: normal;
  overflow-wrap: anywhere;
}
.recommendation-list { margin: 0; padding-left: 22px; }
.recommendation-list li + li { margin-top: 14px; }
.recommendation-list strong { display: block; margin-bottom: 4px; font-weight: 700; }
.recommendation-list span { color: var(--text-secondary); }
.note-box {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel);
  padding: 14px;
  color: var(--text-secondary);
}
.note-box + .table-wrap { margin-top: 12px; }
.footer-note { margin: 0; color: var(--text-muted); }
@media (max-width: 900px) {
  .report-shell { width: min(100% - 20px, 1280px); padding-top: 16px; }
  header, section { padding: 16px; }
  h1 { font-size: 26px; }
  .meta-grid, .metric-grid, .provider-grid, .decision-grid, .signoff-grid {
    grid-template-columns: 1fr; }
  table { min-width: 920px; }
  .compact-table { min-width: 720px; }
}
@media print {
  body { background: #fff; color: #000; }
  .report-shell { width: 100%; padding: 0; }
  header, section { border-color: #c8c8c8; break-inside: avoid;
    page-break-inside: avoid; padding: 16px; }
  .signoff-panel { break-inside: avoid; page-break-inside: avoid; }
  .signoff-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .table-wrap { overflow: visible; }
  table { min-width: 0; }
  .badge { border-color: #999; background: #fff; color: #000; }
}
""".strip()

__all__ = ["EXECUTIVE_REPORT_CSS"]
