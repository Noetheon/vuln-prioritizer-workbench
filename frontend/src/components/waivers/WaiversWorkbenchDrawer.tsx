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
      <SheetContent className="w-[min(100vw,48rem)] overflow-y-auto sm:max-w-none">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>
        <WaiverDrawerContent state={state} />
      </SheetContent>
    </Sheet>
  )
}
