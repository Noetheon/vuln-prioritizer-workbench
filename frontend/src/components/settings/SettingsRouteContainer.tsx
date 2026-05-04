import {
  SettingsWorkbench,
  type SettingsWorkbenchProps,
} from "./SettingsWorkbench"

export type SettingsRouteContainerProps = SettingsWorkbenchProps

export function SettingsRouteContainer(props: SettingsRouteContainerProps) {
  return <SettingsWorkbench {...props} />
}
