export function formatCount(value: number | undefined | null): string {
  return new Intl.NumberFormat("en-US").format(value ?? 0);
}

export function formatPercent(value: number | undefined | null): string {
  if (typeof value !== "number") {
    return "N.A.";
  }
  const percent = value * 100;
  return `${percent >= 10 ? percent.toFixed(1) : percent.toFixed(2)}%`;
}

export function formatScore(value: number | undefined | null, digits = 1): string {
  return typeof value === "number" ? value.toFixed(digits) : "N.A.";
}

export function formatDateTime(value: string | undefined | null): string {
  if (!value) {
    return "N.A.";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

export function formatDate(value: string | undefined | null): string {
  if (!value) {
    return "N.A.";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit"
  }).format(date);
}

export function formatBytes(value: number | undefined | null): string {
  if (!value) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  let current = value;
  let unitIndex = 0;
  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024;
    unitIndex += 1;
  }
  return `${current >= 10 || unitIndex === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[unitIndex]}`;
}

export function compactHash(value: string | undefined | null): string {
  if (!value) {
    return "N.A.";
  }
  return value.length > 14 ? `${value.slice(0, 7)}...${value.slice(-5)}` : value;
}

export function priorityTone(priority: string | undefined | null): string {
  return (priority ?? "neutral").toLowerCase().replaceAll(" ", "-");
}

export function governanceLabel(status: string | undefined | null): string {
  return status ? status.replaceAll("_", " ") : "N.A.";
}

export function topEntries(record: Record<string, number>, limit = 5): Array<[string, number]> {
  return Object.entries(record)
    .sort((first, second) => second[1] - first[1] || first[0].localeCompare(second[0]))
    .slice(0, limit);
}
