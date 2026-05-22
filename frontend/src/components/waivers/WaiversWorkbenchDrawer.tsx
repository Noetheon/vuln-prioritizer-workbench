import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"
import {
  WaiverDrawerContent,
  waiverDrawerDescription,
  waiverDrawerTitle,
} from "./WaiversWorkbenchDrawerContent"

export function WaiverDrawer({ state }: { state: WaiversWorkbenchProps }) {
  const title = waiverDrawerTitle(state.waiverDrawerMode, state.selectedWaiver)
  const description = waiverDrawerDescription(state.waiverDrawerMode)

  return (
    <Sheet
      onOpenChange={(open) => {
        if (!open) {
          state.closeWaiverDrawer()
        }
      }}
      open={state.waiverDrawerMode !== null}
    >
      <SheetContent className="flex w-[min(100vw,52rem)] flex-col overflow-hidden p-0 sm:max-w-none">
        <SheetHeader className="shrink-0 border-b border-[var(--vpw-border-subtle)] p-6 pr-12">
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto p-6">
          <WaiverDrawerContent state={state} />
        </div>
      </SheetContent>
    </Sheet>
  )
}
