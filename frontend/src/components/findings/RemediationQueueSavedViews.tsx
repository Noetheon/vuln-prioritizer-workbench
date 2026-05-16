import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { VpwSegmentedControl } from "@/components/vpw"
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
    <div className="findings-filter-field findings-filter-field--views">
      <span className="vpw-label findings-filter-label">
        View
      </span>
      <VpwSegmentedControl
        className="findings-saved-view-options findings-saved-view-options--segmented"
        label="Finding view"
        onChange={(value) => onSavedViewChange(value as FindingsSavedView)}
        options={findingsSavedViewOptions}
        value={activeSavedView}
      />
      <Select
        onValueChange={(value) => onSavedViewChange(value as FindingsSavedView)}
        value={activeSavedView}
      >
        <SelectTrigger
          aria-label="Finding view"
          className="findings-saved-view-select h-9 w-full text-sm"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {findingsSavedViewOptions.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
