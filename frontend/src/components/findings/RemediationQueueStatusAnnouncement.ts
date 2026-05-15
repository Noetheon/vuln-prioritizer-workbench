export function findingsStatusAnnouncement({
  hasError,
  isLoading,
  pageEnd,
  pageStart,
  totalCount,
}: {
  hasError: boolean
  isLoading: boolean
  pageEnd: number
  pageStart: number
  totalCount: number
}) {
  if (isLoading) return "Findings are loading."
  if (hasError) return "Findings could not be loaded."
  if (totalCount === 0) return "No findings match the current filters."
  return `Showing findings ${pageStart} to ${pageEnd} of ${totalCount}.`
}
