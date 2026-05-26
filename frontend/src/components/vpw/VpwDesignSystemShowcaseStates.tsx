import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VpwDataTable } from "./VpwDataTable"
import { VpwEmptyState } from "./VpwEmptyState"
import { VpwFilterBar } from "./VpwFilterBar"
import { VpwGrid, VpwSection } from "./VpwLayout"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwSegmentedControl } from "./VpwSegmentedControl"
import { VpwSelectionCard } from "./VpwSelectionCard"
import { VpwSkeletonStack } from "./VpwSkeletonStack"
import { VpwStateBlock } from "./VpwStateBlock"
import { VpwStatusBanner } from "./VpwStatusBanner"
import { findingColumns, findingRows } from "./VpwDesignSystemShowcaseData"

export function VpwDesignSystemShowcaseStates() {
  return (
    <>
      <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="flex flex-col gap-4">
          <VpwFilterBar
            actions={<Button variant="outline">Reset</Button>}
            searchPlaceholder="Search CVE, owner, service"
          >
            <VpwSegmentedControl
              label="Priority"
              options={[
                { label: "All", value: "all" },
                { label: "Critical", value: "critical" },
                { label: "KEV", value: "kev" },
              ]}
              value="critical"
            />
          </VpwFilterBar>
          <VpwDataTable
            caption="Design system findings table"
            columns={findingColumns}
            data={findingRows}
            density="standard"
            getRowKey={(row) => row.id}
          />
          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="attack">ATT&CK</TabsTrigger>
            </TabsList>
            <TabsContent value="overview">
              <VpwStatusBanner title="Prioritized queue ready" tone="success">
                Findings are ranked with provider, asset and waiver context.
              </VpwStatusBanner>
            </TabsContent>
            <TabsContent value="evidence">
              <VpwStatusBanner title="Evidence bundle ready" tone="info">
                Report artifacts can be generated for the selected run.
              </VpwStatusBanner>
            </TabsContent>
            <TabsContent value="attack">
              <VpwStatusBanner title="Defensive mapping only" tone="warning">
                ATT&CK context is shown only from reviewed mappings.
              </VpwStatusBanner>
            </TabsContent>
          </Tabs>
        </div>

        <div className="vpw-card flex flex-col gap-5 p-5">
          <VpwSectionHeader
            description="Empty, loading, success and error states share one token set."
            eyebrow="States"
            title="Product State Rules"
          />
          <VpwStatusBanner title="Workspace sample loaded" tone="info">
            Sample state copy stays tied to persisted project evidence.
          </VpwStatusBanner>
          <VpwEmptyState
            description="Import project data to populate this queue."
            title="No findings yet"
          />
          <VpwSkeletonStack rows={3} />
        </div>
      </section>

      <VpwSection>
        <VpwSectionHeader
          eyebrow="Selection and state variants"
          title="Selectable Cards and State Blocks"
        />
        <VpwGrid columns={4}>
          <VpwSelectionCard
            checked
            meta="Current default"
            title="Snapshot mode"
          >
            Deterministic provider data for local evidence.
          </VpwSelectionCard>
          <VpwSelectionCard meta="Available" title="Live provider mode">
            Reserved for explicitly configured provider jobs.
          </VpwSelectionCard>
          <VpwStateBlock title="Report generated" tone="success">
            The evidence bundle is available for download.
          </VpwStateBlock>
          <VpwStateBlock title="Provider unavailable" tone="critical">
            Use the last known snapshot until the source is restored.
          </VpwStateBlock>
        </VpwGrid>
      </VpwSection>
    </>
  )
}
