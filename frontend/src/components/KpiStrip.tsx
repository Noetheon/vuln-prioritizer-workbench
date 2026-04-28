import { formatCount } from "../lib/format";

export interface KpiItem {
  label: string;
  value: number | string;
  detail?: string;
  tone?: "critical" | "high" | "medium" | "low" | "good" | "neutral";
}

interface KpiStripProps {
  items: KpiItem[];
}

export default function KpiStrip({ items }: KpiStripProps) {
  return (
    <section className="kpi-strip" aria-label="Key triage metrics">
      {items.map((item) => (
        <article className={`kpi-card kpi-${item.tone ?? "neutral"}`} key={item.label}>
          <span>{item.label}</span>
          <strong>{typeof item.value === "number" ? formatCount(item.value) : item.value}</strong>
          {item.detail ? <em>{item.detail}</em> : null}
        </article>
      ))}
    </section>
  );
}
