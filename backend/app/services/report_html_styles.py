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
  --report-gutter: 32px;
  --report-max: 1280px;
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
  width: min(var(--report-max), calc(100% - var(--report-gutter)));
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
.eyebrow, dt, .metric span, th, .status-label, .stale-flag, .risk-card-rank {
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
  font-size: 12px;
  line-height: 1rem;
  letter-spacing: 0;
  text-transform: uppercase;
}
.risk-card-cve, .mono-dim, .stale-chip {
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
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
.metric-grid, .provider-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.meta-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0;
  margin-top: 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel);
  overflow: hidden;
}
.meta-grid div {
  min-width: 0;
  padding: 8px 10px;
  border-right: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}
.meta-grid div:nth-child(4n) { border-right: 0; }
.meta-grid div:nth-last-child(-n + 4) { border-bottom: 0; }
.meta-grid dt {
  font-size: 11px;
  line-height: 1;
}
.meta-grid dd {
  margin-top: 3px;
  font-size: 13px;
  line-height: 1.3;
}
.metric, .provider-grid div {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px;
}
.provider-grid div { background: var(--bg-panel); }
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
.campaign-table {
  table-layout: fixed;
  min-width: 1120px;
}
.campaign-table th,
.campaign-table td {
  padding: 9px 10px;
  overflow-wrap: normal;
  word-break: normal;
}
.campaign-table th:nth-child(1),
.campaign-table td:nth-child(1) { width: 7%; }
.campaign-table th:nth-child(2),
.campaign-table td:nth-child(2) { width: 13%; }
.campaign-table th:nth-child(3),
.campaign-table td:nth-child(3) { width: 13%; }
.campaign-table th:nth-child(4),
.campaign-table td:nth-child(4) { width: 15%; }
.campaign-table th:nth-child(5),
.campaign-table td:nth-child(5) { width: 12%; }
.campaign-table th:nth-child(6),
.campaign-table td:nth-child(6) { width: 12%; }
.campaign-table th:nth-child(7),
.campaign-table td:nth-child(7) { width: 11%; }
.campaign-table th:nth-child(8),
.campaign-table td:nth-child(8) { width: 17%; }
.campaign-table td:nth-child(1),
.campaign-table td:nth-child(3) {
  white-space: nowrap;
}
.campaign-cluster-title,
.campaign-cluster-cve {
  display: block;
}
.campaign-cluster-title {
  line-height: 1.25;
}
.campaign-cluster-cve {
  margin-top: 4px;
  overflow-wrap: normal;
}
.campaign-table td:nth-child(4),
.campaign-table td:nth-child(5),
.campaign-table td:nth-child(6),
.campaign-table td:nth-child(8) {
  line-height: 1.3;
}
.campaign-table .signal-row {
  gap: 5px;
}
.campaign-table .badge {
  padding-inline: 7px;
}
.evidence-package-table code {
  white-space: normal;
  overflow-wrap: anywhere;
}
.recommendation-list { margin: 0; padding-left: 22px; }
.recommendation-list li + li { margin-top: 14px; }
.recommendation-list strong { display: block; margin-bottom: 4px; font-weight: 700; }
.recommendation-list span { color: var(--text-secondary); }
.recommendation-table td:nth-child(1) { white-space: nowrap; }
.mono-dim { font-size: 12px; color: var(--text-muted); }
.risk-index {
  margin: 0 0 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-card);
  padding: 16px;
  box-shadow: inset 3px 0 0 var(--violet);
}
.risk-index[data-tone="critical"] { box-shadow: inset 3px 0 0 var(--red); }
.risk-index[data-tone="warning"] { box-shadow: inset 3px 0 0 var(--amber); }
.risk-index[data-tone="success"] { box-shadow: inset 3px 0 0 var(--green); }
.risk-index-value {
  display: block;
  margin: 6px 0 2px;
  font-size: 56px;
  line-height: 1;
  font-weight: 760;
  font-variant-numeric: tabular-nums;
}
.risk-index-max { font-size: 20px; font-weight: 700; color: var(--text-muted); }
.risk-index[data-tone="critical"] .risk-index-value { color: var(--red); }
.risk-index[data-tone="warning"] .risk-index-value { color: var(--amber); }
.risk-index[data-tone="success"] .risk-index-value { color: var(--green); }
.risk-index-band { margin: 0 0 12px; font-weight: 680; color: var(--text-secondary); }
.risk-gauge {
  position: relative;
  height: 8px;
  border-radius: 9999px;
  background: linear-gradient(
    90deg, var(--green) 0 40%, var(--amber) 40% 70%, var(--red) 70% 100%);
}
.risk-gauge-needle {
  position: absolute;
  top: -4px;
  width: 3px;
  height: 16px;
  background: var(--text-primary);
  border-radius: 2px;
  transform: translateX(-50%);
}
.risk-gauge-scale {
  display: flex;
  justify-content: space-between;
  margin-top: 6px;
  color: var(--text-muted);
  font-size: 12px;
}
.risk-index-foot { margin: 12px 0 0; color: var(--text-muted); }
.risk-scenario {
  display: grid;
  grid-template-columns: minmax(210px, 0.9fr) minmax(520px, 2.2fr) minmax(280px, 1.15fr);
  margin: 0 0 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-card);
  overflow: hidden;
}
.risk-scenario > section {
  margin: 0;
  border: 0;
  border-right: 1px solid var(--border);
  border-radius: 0;
  background: var(--bg-card);
  padding: 16px;
}
.risk-scenario > section:last-child { border-right: 0; }
.risk-scenario-index { box-shadow: inset 3px 0 0 var(--violet); }
.risk-scenario[data-tone="critical"] .risk-scenario-index { box-shadow: inset 3px 0 0 var(--red); }
.risk-scenario[data-tone="warning"] .risk-scenario-index { box-shadow: inset 3px 0 0 var(--amber); }
.risk-scenario[data-tone="success"] .risk-scenario-index { box-shadow: inset 3px 0 0 var(--green); }
.risk-scenario-index-value {
  display: block;
  margin: 8px 0 2px;
  font-size: 58px;
  line-height: 0.92;
  font-weight: 850;
  font-variant-numeric: tabular-nums;
}
.risk-scenario[data-tone="critical"] .risk-scenario-index-value { color: var(--red); }
.risk-scenario[data-tone="warning"] .risk-scenario-index-value { color: var(--amber); }
.risk-scenario[data-tone="success"] .risk-scenario-index-value { color: var(--green); }
.risk-scenario-change {
  margin: 0 0 12px;
  color: var(--green);
  font-weight: 680;
}
.risk-scenario-change strong {
  font-size: 17px;
  font-variant-numeric: tabular-nums;
}
.risk-scenario-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.risk-scenario-legend {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 650;
  white-space: nowrap;
}
.risk-scenario-legend b {
  display: inline-block;
  width: 14px;
  height: 8px;
  border-radius: 4px;
}
.legend-actual {
  border: 1px solid #f3a6a6;
  background: var(--bg-critical);
}
.legend-projected { border: 1px dashed var(--green); background: var(--bg-success); }
.legend-target {
  height: 0 !important;
  border-top: 1px dashed var(--green);
  background: transparent;
}
.risk-projection-svg {
  display: block;
  width: 100%;
  height: auto;
}
.risk-projection-grid-line {
  stroke: #dedede;
  stroke-width: 1;
}
.risk-projection-axis-label,
.risk-projection-bar-label,
.risk-projection-bar-detail,
.risk-projection-target-label,
.risk-projection-today-label {
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
  fill: var(--text-muted);
  font-size: 12px;
  font-weight: 700;
}
.risk-projection-axis-label { text-anchor: end; }
.risk-projection-today {
  stroke: var(--text-primary);
  stroke-width: 1.6;
  stroke-linecap: round;
  stroke-dasharray: 2 5;
}
.risk-projection-today-label,
.risk-projection-bar-value {
  fill: var(--text-primary);
  font-weight: 850;
  text-anchor: middle;
}
.risk-projection-target {
  stroke: var(--green);
  stroke-width: 1.5;
  stroke-dasharray: 7 5;
}
.risk-projection-target-label {
  fill: var(--green);
  font-weight: 850;
  paint-order: stroke;
  stroke: var(--bg-card);
  stroke-linejoin: round;
  stroke-width: 5px;
  text-anchor: end;
}
.risk-projection-bar-fill {
  fill: #f4f4f5;
  stroke: none;
}
.risk-projection-bar-cap {
  fill: var(--text-muted);
}
.risk-projection-bar[data-tone="critical"] .risk-projection-bar-fill {
  fill: url("#risk-report-grad-critical");
}
.risk-projection-bar[data-tone="critical"] .risk-projection-bar-cap {
  fill: var(--red);
}
.risk-projection-bar[data-tone="elevated"] .risk-projection-bar-fill {
  fill: url("#risk-report-grad-elevated");
}
.risk-projection-bar[data-tone="elevated"] .risk-projection-bar-cap {
  fill: var(--amber);
}
.risk-projection-bar[data-tone="low"] .risk-projection-bar-fill,
.risk-projection-bar[data-tone="success"] .risk-projection-bar-fill {
  fill: url("#risk-report-grad-success");
  stroke: rgba(4, 120, 87, 0.5);
  stroke-dasharray: 4 4;
  stroke-width: 1.2;
}
.risk-projection-bar[data-tone="low"] .risk-projection-bar-cap,
.risk-projection-bar[data-tone="success"] .risk-projection-bar-cap {
  fill: var(--green);
}
.risk-projection-bar[data-tone="projected"] .risk-projection-bar-fill {
  fill: url("#risk-report-grad-projected");
  stroke: rgba(4, 120, 87, 0.46);
  stroke-dasharray: 4 4;
  stroke-width: 1.2;
}
.risk-projection-bar[data-tone="projected"] .risk-projection-bar-cap {
  fill: var(--green);
}
.risk-projection-bar-value {
  font-size: 14px;
  paint-order: stroke;
  stroke: var(--bg-card);
  stroke-linejoin: round;
  stroke-width: 5px;
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
}
.risk-projection-bar-label {
  fill: var(--text-primary);
  font-size: 12.5px;
  font-weight: 850;
  text-anchor: middle;
}
.risk-projection-bar-detail { text-anchor: middle; }
.risk-scenario-readout {
  display: flex;
  flex-wrap: wrap;
  gap: 7px 10px;
  align-items: center;
  margin-top: 2px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel);
  padding: 8px 10px;
}
.risk-scenario-readout-chip {
  display: inline-flex;
  align-items: center;
  border-radius: 5px;
  background: var(--text-primary);
  color: var(--bg-card);
  padding: 3px 8px;
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
  font-size: 11px;
  font-weight: 850;
  line-height: 1;
  white-space: nowrap;
}
.risk-scenario-readout-text {
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 700;
  line-height: 1.4;
}
.risk-scenario-readout-text strong {
  color: var(--text-primary);
  font-weight: 850;
  font-variant-numeric: tabular-nums;
}
.risk-scenario-readout-warn { color: var(--amber) !important; }
.risk-scenario-note,
.risk-scenario-reducer-lede {
  margin: 8px 0 0;
  color: var(--text-muted);
  font-size: 12px;
}
.risk-scenario-reducers ol {
  display: grid;
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.risk-scenario-reducer {
  display: grid;
  gap: 4px;
  padding: 0 0 10px;
  border-top: 1px solid var(--border);
}
.risk-scenario-reducer:first-child {
  padding-top: 0;
  border-top: 0;
}
.risk-scenario-reducer-main {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  align-items: start;
}
.risk-scenario-reducer-title {
  overflow-wrap: anywhere;
  font-weight: 850;
  line-height: 1.22;
}
.risk-scenario-reducer-main strong {
  color: var(--red);
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
  font-weight: 850;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.risk-scenario-reducer-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 5px;
  align-items: center;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 750;
  line-height: 1.3;
}
.risk-scenario-reducer-context {
  display: block;
  overflow: hidden;
  color: var(--text-muted);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.risk-reducer-tag {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  border-radius: 4px;
  background: var(--red);
  color: var(--bg-card);
  padding: 2px 5px;
  font-family:
    "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
    Consolas, monospace;
  font-size: 10px;
  font-weight: 850;
  line-height: 1.2;
  text-transform: uppercase;
  white-space: nowrap;
}
.risk-reducer-tag--kev { background: #fee2e2; color: var(--red); }
.risk-reducer-tag--epss { background: #dbeafe; color: var(--blue); }
.risk-reducer-tag--cvss {
  border: 1px solid #d4d4d8;
  background: var(--bg-card);
  color: var(--text-secondary);
}
.risk-scenario-reducer-track {
  display: block;
  height: 4px;
  margin-top: 3px;
  border-radius: 9999px;
  background: #f0f0f0;
  overflow: hidden;
}
.risk-scenario-reducer-track span {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: rgba(23, 23, 23, 0.78);
}
.stale-alert {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  border: 1px solid #fecaca;
  border-left: 4px solid var(--red);
  border-radius: var(--radius-sm);
  background: var(--bg-critical);
  padding: 16px;
}
.stale-flag {
  flex: none;
  border-radius: var(--radius-sm);
  background: var(--red);
  color: #fff;
  padding: 4px 9px;
  font-weight: 680;
  white-space: nowrap;
}
.stale-body { min-width: 0; }
.stale-body strong { color: #7c2d12; }
.stale-text { margin: 6px 0 0; color: var(--text-secondary); }
.stale-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.stale-chip {
  border: 1px solid var(--border);
  border-radius: 9999px;
  background: var(--bg-card);
  padding: 4px 11px;
  font-size: 12px;
}
.stale-chip b { color: var(--red); font-weight: 680; }
.risk-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  align-items: start;
}
.risk-card {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-card);
  padding: 16px;
  box-shadow: inset 3px 0 0 var(--red);
}
.risk-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 8px;
}
.risk-card-rank { color: var(--red); font-weight: 650; }
.risk-card-cve { margin: 0; color: var(--text-muted); font-size: 12px; }
.risk-card-name { margin: 4px 0 0; font-size: 17px; }
.risk-card-scope { margin: 6px 0 10px; color: var(--text-secondary); }
.risk-card .signal-row { margin-bottom: 12px; }
.risk-card-action {
  margin: 0;
  padding-top: 10px;
  border-top: 1px solid var(--border);
  color: var(--text-secondary);
}
.risk-card-action .status-label { display: block; margin-bottom: 3px; color: var(--red); }
.note-box {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-panel);
  padding: 14px;
  color: var(--text-secondary);
}
.note-box + .table-wrap { margin-top: 12px; }
.footer-note { margin: 0; color: var(--text-muted); }
@media (min-width: 1680px) {
  :root {
    --report-gutter: 56px;
    --report-max: 1600px;
  }
  .risk-scenario {
    grid-template-columns: minmax(230px, 0.75fr) minmax(660px, 2.4fr) minmax(320px, 1.15fr);
  }
  .campaign-table {
    min-width: 1280px;
  }
}
@media (min-width: 2200px) {
  :root {
    --report-gutter: 96px;
    --report-max: 2160px;
  }
  header, section {
    padding: 22px;
  }
  .risk-scenario {
    grid-template-columns: minmax(270px, 0.72fr) minmax(860px, 2.75fr) minmax(390px, 1.12fr);
  }
  .campaign-table {
    min-width: 1600px;
  }
}
@media (max-width: 900px) {
  .report-shell { width: min(100% - 20px, 1280px); padding-top: 16px; }
  header, section { padding: 16px; }
  h1 { font-size: 26px; }
  .meta-grid, .metric-grid, .provider-grid, .decision-grid, .signoff-grid, .risk-cards {
    grid-template-columns: 1fr; }
  .meta-grid div,
  .meta-grid div:nth-child(4n),
  .meta-grid div:nth-last-child(-n + 4) {
    border-right: 0;
    border-bottom: 1px solid var(--border);
  }
  .meta-grid div:last-child { border-bottom: 0; }
  .meta-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .meta-grid div { border-right: 1px solid var(--border); }
  .meta-grid div:nth-child(2n) { border-right: 0; }
  .meta-grid div:nth-last-child(-n + 2) { border-bottom: 0; }
  .risk-scenario { grid-template-columns: 1fr; }
  .risk-scenario > section {
    border-right: 0;
    border-bottom: 1px solid var(--border);
  }
  .risk-scenario > section:last-child { border-bottom: 0; }
  .risk-scenario-section-head { align-items: flex-start; flex-direction: column; }
  .risk-scenario-legend { white-space: normal; }
  table { min-width: 920px; }
  .compact-table { min-width: 720px; }
}
@media print {
  body { background: #fff; color: #000; }
  .report-shell { width: 100%; padding: 0; }
  header, section { border-color: #c8c8c8; break-inside: avoid;
    page-break-inside: avoid; padding: 16px; }
  .signoff-panel { break-inside: avoid; page-break-inside: avoid; }
  .risk-index, .risk-scenario, .stale-alert, .risk-card {
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .risk-scenario { grid-template-columns: 0.9fr 1.9fr 1.2fr; }
  .risk-scenario > section { padding: 12px; }
  .signoff-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .table-wrap { overflow: visible; }
  table { min-width: 0; }
  .badge { border-color: #999; background: #fff; color: #000; }
}
""".strip()

__all__ = ["EXECUTIVE_REPORT_CSS"]
