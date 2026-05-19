import {
  Activity,
  Database,
  FileArchive,
  ShieldCheck,
} from "lucide-react"

import { VpwAppFrame } from "./VpwAppFrame"
import { VpwGrid } from "./VpwLayout"
import { VpwMetricCard } from "./VpwMetricCard"

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
        <VpwGrid columns={4}>
          <VpwMetricCard label="Critical" tone="critical" value="12" />
          <VpwMetricCard label="KEV" tone="warning" value="5" />
          <VpwMetricCard label="Runs" tone="info" value="28" />
          <VpwMetricCard label="Evidence" tone="success" value="9" />
        </VpwGrid>
      </VpwAppFrame>

      <section className="grid gap-4 lg:grid-cols-4">
        <VpwMetricCard
          description="Open high-impact findings"
          icon={<ShieldCheck className="h-5 w-5" aria-hidden="true" />}
          label="Critical"
          tone="critical"
          value="12"
        />
        <VpwMetricCard
          description="Known exploited signals"
          icon={<Activity className="h-5 w-5" aria-hidden="true" />}
          label="KEV"
          tone="warning"
          value="5"
        />
        <VpwMetricCard
          description="Generated artifacts"
          icon={<FileArchive className="h-5 w-5" aria-hidden="true" />}
          label="Evidence"
          tone="success"
          value="9"
        />
        <VpwMetricCard
          description="Provider snapshot mode"
          icon={<Database className="h-5 w-5" aria-hidden="true" />}
          label="Providers"
          tone="info"
          value="Fresh"
        />
      </section>
    </>
  )
}
