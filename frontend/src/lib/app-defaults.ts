import type {
  AssetExposure,
  AttackSourceCapabilityPublic,
  FindingPriority,
  FindingStatus,
  FindingsReadProjectFindingsData,
  ImportsService,
} from "../api-client"
import type { ImportInputType } from "./import-format-metadata.ts"

export type ProjectFormState = {
  name: string
  description: string
}

export const emptyProjectForm: ProjectFormState = {
  name: "",
  description: "",
}

export type ImportFormat = ImportInputType
export type AttackImportSource = AttackSourceCapabilityPublic["value"]

export type ImportWizardState = {
  attackMappingFile: string
  attackSource: AttackImportSource
  attackTechniqueMetadataFile: string
  assetContextFile: File | null
  file: File | null
  inputType: ImportFormat | ""
  lockedProviderData: boolean
  providerSnapshotFile: string
  vexFile: File | null
}

export const demoProviderSnapshotFile = "demo_provider_snapshot.json"

export const defaultImportWizardState: ImportWizardState = {
  attackMappingFile: "",
  attackSource: "none",
  attackTechniqueMetadataFile: "",
  assetContextFile: null,
  file: null,
  inputType: "",
  lockedProviderData: false,
  providerSnapshotFile: "",
  vexFile: null,
}

export function withDemoProviderSnapshot(
  state: ImportWizardState,
): ImportWizardState {
  return {
    ...state,
    lockedProviderData: true,
    providerSnapshotFile: demoProviderSnapshotFile,
  }
}

export type ImportUploadFormData = Parameters<
  typeof ImportsService.importProjectUpload
>[0]["bodyImportsImportProjectUpload"]

export type FindingsSort = NonNullable<FindingsReadProjectFindingsData["sort"]>
export type FindingsDirection = NonNullable<
  FindingsReadProjectFindingsData["direction"]
>

export type KevFilter = "" | "true" | "false"

export type FindingFilters = {
  cvssMax: string
  cvssMin: string
  epssMax: string
  epssMin: string
  exposure: "" | AssetExposure
  kev: KevFilter
  ownerService: string
  priority: "" | FindingPriority
  query: string
  status: "" | FindingStatus
}

export const defaultFindingFilters: FindingFilters = {
  cvssMax: "",
  cvssMin: "",
  epssMax: "",
  epssMin: "",
  exposure: "",
  kev: "",
  ownerService: "",
  priority: "",
  query: "",
  status: "",
}

export const findingPageSizes = [1, 10, 25, 50] as const

export type FindingDetailTab =
  | "decision"
  | "evidence"
  | "occurrences"
  | "ttp"
  | "history"
  | "governance"

export const findingPriorityOptions: FindingPriority[] = [
  "critical",
  "high",
  "medium",
  "low",
]

export const findingStatusOptions: FindingStatus[] = [
  "open",
  "in_review",
  "remediating",
  "fixed",
  "accepted",
  "suppressed",
]

export const findingExposureOptions: AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]

export const findingSortOptions: { label: string; value: FindingsSort }[] = [
  { label: "Operational", value: "operational" },
  { label: "Priority", value: "priority" },
  { label: "Score", value: "score" },
  { label: "CVE", value: "cve" },
  { label: "Status", value: "status" },
  { label: "EPSS", value: "epss" },
  { label: "CVSS", value: "cvss" },
  { label: "KEV", value: "kev" },
  { label: "Last Seen", value: "last_seen" },
]

export const evidenceTimeline = [
  "Provider snapshot locked",
  "Trivy import normalized",
  "Evidence bundle verified",
]
