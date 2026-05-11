export const vpwTokens = {
  color: {
    brand: {
      primary: "#2563EB",
      teal: "#14B8A6",
      success: "#22C55E",
      warning: "#F59E0B",
      critical: "#EF4444",
      support: "#6366F1",
      navy: "#0B1020",
    },
    neutral: {
      950: "#0B1220",
      900: "#111827",
      800: "#1F2937",
      700: "#374151",
      600: "#4B5563",
      500: "#6B7280",
      400: "#9CA3AF",
      300: "#D1D5DB",
      200: "#E5E7EB",
      100: "#F3F4F6",
      50: "#F8FAFC",
      25: "#FAFBFD",
    },
    surface: {
      app: "#FAFBFD",
      page: "#FFFFFF",
      card: "#FFFFFF",
      panel: "#F8FAFC",
      info: "#EFF6FF",
      success: "#ECFDF5",
      warning: "#FFFBEB",
      critical: "#FEF2F2",
    },
    border: {
      default: "#E5E7EB",
      subtle: "#EEF2F7",
      strong: "#D1D5DB",
      focus: "#3B82F6",
    },
  },
  radius: {
    sm: "4px",
    md: "6px",
    lg: "8px",
    xl: "8px",
    pill: "9999px",
  },
  shadow: {
    0: "none",
    1: "0 1px 2px rgba(2, 6, 23, 0.04)",
    2: "0 4px 12px rgba(2, 6, 23, 0.06)",
    3: "0 12px 24px rgba(2, 6, 23, 0.08)",
  },
  layout: {
    maxWidth: "1920px",
    pagePadding: {
      base: "1rem",
      sm: "1.5rem",
      lg: "2rem",
      xl: "2.5rem",
      xxl: "3rem",
    },
  },
} as const

export type VpwTokens = typeof vpwTokens
