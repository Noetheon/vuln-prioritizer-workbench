import { mkdirSync } from "node:fs"
import path from "node:path"

const updateTrackedEvidence = process.env.VPW_UPDATE_DOCS_EVIDENCE === "1"

const evidenceBaseDir = updateTrackedEvidence
  ? path.join(process.cwd(), "..", "archive", "vpw-evidence")
  : path.join(process.cwd(), "test-results", "evidence")

export function evidenceScreenshotPath(...segments: string[]) {
  const screenshotPath = path.join(evidenceBaseDir, ...segments)
  mkdirSync(path.dirname(screenshotPath), { recursive: true })
  return screenshotPath
}
