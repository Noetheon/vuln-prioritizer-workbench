import { VpwBadge } from "./VpwBadge"
import { VpwBreadcrumbs } from "./VpwBreadcrumbs"
import { VpwPageContainer } from "./VpwPageContainer"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwDesignSystemShowcaseEvidence } from "./VpwDesignSystemShowcaseEvidence"
import { VpwDesignSystemShowcaseFoundations } from "./VpwDesignSystemShowcaseFoundations"

export function VpwDesignSystemShowcase() {
  return (
    <VpwPageContainer className="flex flex-col gap-8">
      <VpwSectionHeader
        actions={<VpwBadge tone="info">Precision Light Analyst</VpwBadge>}
        description="Reusable VPW tokens, product components, controls, read/write evidence patterns and analyst product states."
        eyebrow="VPW Design System"
        title="Precision Light Analyst Design Set"
      />

      <VpwBreadcrumbs
        items={[
          { label: "VPW" },
          { label: "Design system" },
          { label: "Precision Light Analyst", current: true },
        ]}
      />

      <VpwDesignSystemShowcaseFoundations />
      <VpwDesignSystemShowcaseEvidence />
    </VpwPageContainer>
  )
}
