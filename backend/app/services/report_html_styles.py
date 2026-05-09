"""Executive HTML report stylesheet."""

from __future__ import annotations

EXECUTIVE_REPORT_CSS = """
:root {
  color-scheme: light;
  --bg: #f6f8fb;
  --surface: #ffffff;
  --text: #18202f;
  --muted: #5d6a7d;
  --border: #d8dee8;
  --accent: #1665d8;
  --accent-soft: #e8f1ff;
  --critical: #b42318;
  --high: #b54708;
  --medium: #8a6116;
  --low: #186a3b;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
.report-shell {
  width: min(1160px, calc(100% - 32px));
  margin: 0 auto;
  padding: 32px 0 48px;
}
header,
section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 18px;
  padding: 24px;
}
h1,
h2,
h3,
p {
  margin-top: 0;
}
h1 {
  margin-bottom: 10px;
  font-size: 32px;
  line-height: 1.15;
}
h2 {
  margin-bottom: 12px;
  font-size: 22px;
  line-height: 1.25;
}
.eyebrow {
  margin-bottom: 6px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}
.lede {
  max-width: 840px;
  color: var(--muted);
}
.section-heading {
  margin-bottom: 14px;
}
.meta-grid,
.metric-grid,
.provider-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.meta-grid {
  margin: 18px 0 0;
}
.meta-grid div,
.metric,
.provider-grid div {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  background: #fbfcfe;
}
dt,
.metric span {
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
dd {
  margin: 4px 0 0;
  overflow-wrap: anywhere;
}
.metric strong {
  display: block;
  margin-top: 4px;
  font-size: 26px;
  line-height: 1.1;
}
.table-wrap {
  overflow-x: auto;
}
table {
  width: 100%;
  min-width: 920px;
  border-collapse: collapse;
}
th,
td {
  border-bottom: 1px solid var(--border);
  padding: 10px 8px;
  text-align: left;
  vertical-align: top;
}
th {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}
td {
  overflow-wrap: anywhere;
}
.badge {
  display: inline-flex;
  border-radius: 999px;
  padding: 2px 8px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  white-space: nowrap;
}
tbody td:nth-child(-n + 7),
thead th:nth-child(-n + 7) {
  white-space: nowrap;
}
.badge-critical {
  background: #fee4e2;
  color: var(--critical);
}
.badge-high {
  background: #ffead5;
  color: var(--high);
}
.badge-medium {
  background: #fef3c7;
  color: var(--medium);
}
.badge-low {
  background: #dcfae6;
  color: var(--low);
}
.recommendation-list {
  margin: 0;
  padding-left: 24px;
}
.recommendation-list li + li {
  margin-top: 12px;
}
.recommendation-list strong {
  display: block;
}
.empty-state {
  color: var(--muted);
}
@media (max-width: 820px) {
  .report-shell {
    width: min(100% - 20px, 1160px);
    padding-top: 16px;
  }
  header,
  section {
    padding: 16px;
  }
  h1 {
    font-size: 26px;
  }
  .meta-grid,
  .metric-grid,
  .provider-grid {
    grid-template-columns: 1fr;
  }
}
@media print {
  body {
    background: #ffffff;
    color: #000000;
  }
  .report-shell {
    width: 100%;
    padding: 0;
  }
  header,
  section {
    border-color: #c8c8c8;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .table-wrap {
    overflow: visible;
  }
  table {
    min-width: 0;
  }
}
""".strip()

__all__ = ["EXECUTIVE_REPORT_CSS"]
