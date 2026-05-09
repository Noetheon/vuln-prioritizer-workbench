import { AssetsWorkbench } from "../../components/assets"
import { useAssetsRouteState } from "./useAssetsRouteState"

export function AssetsRoute() {
  return <AssetsWorkbench {...useAssetsRouteState()} />
}
