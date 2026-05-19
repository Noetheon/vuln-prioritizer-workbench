import { Download } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { VpwBadge } from "./VpwBadge"
import { VpwField } from "./VpwField"
import {
  VpwElevationSpec,
  VpwSpacingSpec,
  VpwTypographySpec,
} from "./VpwFoundationSpecs"
import { VpwGrid, VpwPanel } from "./VpwLayout"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwTokenSwatch } from "./VpwTokenSwatch"
import { VpwToolbar, VpwToolbarGroup } from "./VpwToolbar"

export function VpwDesignSystemShowcaseControls() {
  return (
    <>
      <section className="grid gap-4 xl:grid-cols-2">
        <div className="vpw-panel flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Token swatches are based on the installed kit variables."
            eyebrow="Foundations"
            title="Color and Surface Tokens"
          />
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <VpwTokenSwatch
              name="Ink"
              usage="Primary actions and product chrome"
              value="#171717"
            />
            <VpwTokenSwatch
              name="Link Blue"
              usage="Focus and informational states"
              value="#0070F3"
            />
            <VpwTokenSwatch
              name="Success"
              usage="Healthy and verified states"
              value="#047857"
            />
            <VpwTokenSwatch
              name="Critical"
              usage="Critical and destructive states"
              value="#C40000"
            />
          </div>
        </div>

        <div className="vpw-panel flex flex-col gap-4 p-5">
          <VpwSectionHeader
            description="Toolbar, field wrappers and primitive controls."
            eyebrow="Controls"
            title="Forms and Actions"
          />
          <VpwToolbar label="Design system controls">
            <VpwToolbarGroup>
              <Button>
                <Download aria-hidden="true" data-icon="inline-start" />
                Generate report
              </Button>
              <Button variant="outline">Verify bundle</Button>
              <Button variant="ghost">Refresh</Button>
            </VpwToolbarGroup>
            <VpwToolbarGroup>
              <VpwBadge tone="success">Verified</VpwBadge>
              <VpwBadge tone="warning">Demo</VpwBadge>
            </VpwToolbarGroup>
          </VpwToolbar>
          <div className="grid gap-3 sm:grid-cols-2">
            <VpwField
              description="Used by imports, reports and waivers."
              label="Project"
            >
              <Input defaultValue="Payments Service" />
            </VpwField>
            <VpwField label="Priority">
              <Select defaultValue="critical">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                </SelectContent>
              </Select>
            </VpwField>
            <VpwField className="sm:col-span-2" label="Evidence note">
              <Textarea defaultValue="Reviewed provider snapshot, asset exposure, waiver state and evidence bundle readiness." />
            </VpwField>
          </div>
        </div>
      </section>

      <VpwGrid columns={3}>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader eyebrow="Typography" title="Type Scale" />
          <VpwTypographySpec />
        </VpwPanel>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader eyebrow="Spacing" title="Rhythm and Radius" />
          <VpwSpacingSpec />
        </VpwPanel>
        <VpwPanel className="flex flex-col gap-4">
          <VpwSectionHeader eyebrow="Elevation" title="Shadow Scale" />
          <VpwElevationSpec />
        </VpwPanel>
      </VpwGrid>
    </>
  )
}
