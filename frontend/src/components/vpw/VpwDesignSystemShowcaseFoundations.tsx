import { VpwDesignSystemShowcaseControls } from "./VpwDesignSystemShowcaseControls"
import { VpwDesignSystemShowcaseFrame } from "./VpwDesignSystemShowcaseFrame"
import { VpwDesignSystemShowcaseStates } from "./VpwDesignSystemShowcaseStates"

export function VpwDesignSystemShowcaseFoundations() {
  return (
    <>
      <VpwDesignSystemShowcaseFrame />
      <VpwDesignSystemShowcaseControls />
      <VpwDesignSystemShowcaseStates />
    </>
  )
}
