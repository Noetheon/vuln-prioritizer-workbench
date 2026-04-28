import type { ReactNode } from "react";

import { priorityTone } from "../lib/format";

interface BadgeProps {
  children: ReactNode;
  tone?: string;
}

export function Badge({ children, tone = "neutral" }: BadgeProps) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function PriorityBadge({ priority }: { priority: string }) {
  return <Badge tone={priorityTone(priority)}>{priority}</Badge>;
}

export function SignalBadge({ active, children }: { active: boolean; children: ReactNode }) {
  return <span className={`signal-badge ${active ? "is-active" : ""}`}>{children}</span>;
}
