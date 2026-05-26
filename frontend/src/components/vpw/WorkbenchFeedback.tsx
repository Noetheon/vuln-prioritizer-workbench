import { VpwEmptyState, type VpwEmptyStateProps } from "./VpwEmptyState"
import {
  VpwStatusBanner,
  type VpwStatusBannerProps,
  type VpwStatusBannerTone,
} from "./VpwStatusBanner"

export type EmptyStateProps = VpwEmptyStateProps

export function EmptyState(props: EmptyStateProps) {
  return <VpwEmptyState {...props} />
}

export type CalloutProps = Omit<VpwStatusBannerProps, "tone"> & {
  severity?: VpwStatusBannerTone
}

export function Callout({ severity = "info", ...props }: CalloutProps) {
  return <VpwStatusBanner tone={severity} {...props} />
}
