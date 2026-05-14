import { Button } from "@/components/ui/button"
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
    <fieldset className="findings-saved-view-group">
      <legend className="text-[11px] font-semibold uppercase text-muted-foreground">
        View
      </legend>
      <div className="findings-saved-view-options">
        {findingsSavedViewOptions.map((option) => {
          const active = option.value === activeSavedView
          return (
            <Button
              aria-pressed={active}
              className="h-8 px-2 text-xs"
              key={option.value}
              onClick={() => onSavedViewChange(option.value)}
              size="sm"
              type="button"
              variant={active ? "secondary" : "ghost"}
            >
              {option.label}
            </Button>
          )
        })}
      </div>
    </fieldset>
  )
}
