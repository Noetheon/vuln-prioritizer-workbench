import { AlertTriangle, FolderPlus } from "lucide-react";
import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
  tone?: "neutral" | "warning";
}

export default function EmptyState({ title, children, action, tone = "neutral" }: EmptyStateProps) {
  const Icon = tone === "warning" ? AlertTriangle : FolderPlus;
  return (
    <section className="empty-state">
      <Icon aria-hidden="true" size={28} />
      <h2>{title}</h2>
      {children ? <p>{children}</p> : null}
      {action ? <div className="empty-action">{action}</div> : null}
    </section>
  );
}
