import { VpwField, VpwSegmentedControl } from "@/components/vpw"
import {
  findingsSavedViewOptions,
  type FindingsSavedView,
} from "./remediation-queue-model"

type RemediationQueueSavedViewsProps = {
  activeSavedView: FindingsSavedView
  onSavedViewChange: (view: FindingsSavedView) => void
}

export function RemediationQueueSavedViews({
  activeSavedView,
  onSavedViewChange,
}: RemediationQueueSavedViewsProps) {
  return (
    <VpwField className="vpw-filter-field vpw-filter-field--lg" label="View">
      <VpwSegmentedControl
        label="Finding view"
        onChange={(value) => onSavedViewChange(value as FindingsSavedView)}
        options={findingsSavedViewOptions}
        value={activeSavedView}
      />
    </VpwField>
  )
}
