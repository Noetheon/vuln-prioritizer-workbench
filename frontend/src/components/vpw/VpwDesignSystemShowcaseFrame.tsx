import {
  Activity,
  Database,
  FileArchive,
  ShieldCheck,
} from "lucide-react"

import { VpwAppFrame } from "./VpwAppFrame"
import { VpwCompactMetric, VpwMetricStrip } from "./VpwLayout"

export function VpwDesignSystemShowcaseFrame() {
  return (
    <>
      <VpwAppFrame
        navItems={[
          { label: "Dashboard", icon: Activity, active: true },
          { label: "Findings", icon: ShieldCheck },
          { label: "Evidence Center", icon: FileArchive },
          { label: "Providers", icon: Database },
        ]}
        statusItems={[
          { label: "Provider", value: "Snapshot mode" },
          { label: "EPSS", value: "Fresh" },
          { label: "KEV", value: "Loaded" },
          { label: "Evidence", value: "Ready" },
        ]}
        title="Risk Operations"
      >
        <VpwMetricStrip minCardWidth="8rem">
          <VpwCompactMetric label="Critical" tone="critical" value="12" />
          <VpwCompactMetric label="KEV" tone="warning" value="5" />
          <VpwCompactMetric label="Runs" tone="info" value="28" />
          <VpwCompactMetric label="Evidence" tone="success" value="9" />
        </VpwMetricStrip>
      </VpwAppFrame>

      <VpwMetricStrip minCardWidth="12rem">
        <VpwCompactMetric
          description="Open high-impact findings"
          icon={<ShieldCheck className="h-5 w-5" aria-hidden="true" />}
          label="Critical"
          tone="critical"
          value="12"
        />
        <VpwCompactMetric
          description="Known exploited signals"
          icon={<Activity className="h-5 w-5" aria-hidden="true" />}
          label="KEV"
          tone="warning"
          value="5"
        />
        <VpwCompactMetric
          description="Generated artifacts"
          icon={<FileArchive className="h-5 w-5" aria-hidden="true" />}
          label="Evidence"
          tone="success"
          value="9"
        />
        <VpwCompactMetric
          description="Provider snapshot mode"
          icon={<Database className="h-5 w-5" aria-hidden="true" />}
          label="Providers"
          tone="info"
          value="Fresh"
        />
      </VpwMetricStrip>
    </>
  )
}
