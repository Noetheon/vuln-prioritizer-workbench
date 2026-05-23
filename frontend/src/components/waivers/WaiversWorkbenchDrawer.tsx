import { DetailDrawer } from "@/components/vpw"
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
    <DetailDrawer
      className="w-[min(100vw,52rem)] sm:max-w-none"
      description={description}
      onOpenChange={(open) => {
        if (!open) {
          state.closeWaiverDrawer()
        }
      }}
      open={state.waiverDrawerMode !== null}
      title={title}
    >
      <WaiverDrawerContent state={state} />
    </DetailDrawer>
  )
}
