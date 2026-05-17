import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import test from "node:test"

import {
  failedRunCause,
  fileSizeLabel,
  formatDateTime,
  formatDisplayType,
  formatExpectedFields,
  hasOptionalContext,
  importRunTimelineItems,
  importSubmitDisabled,
  jsonPreview,
  metadataRows,
  optionalContextLabels,
  runFileLabel,
  runTone,
  selectedFormat,
  uploadProgress,
} from "../src/components/imports/imports-workbench-model.ts"
import {
  defaultImportWizardState,
  demoProviderSnapshotFile,
  withDemoProviderSnapshot,
  workbenchImportFormats,
} from "../src/lib/app-defaults.ts"
import {
  acceptedFileInputValue,
  buildImportReadinessChecks,
  buildParserPreview,
  fileMatchesAcceptedExtension,
  getAcceptedMimeTypes,
  initialParserPreview,
  readinessBlocksImport,
  SUPPORTED_IMPORT_FORMATS,
  type ParserPreview,
} from "../src/lib/import-format-metadata.ts"
import { buildImportUploadFormData } from "../src/workbench/import-upload-payload.ts"

test("import model derives display labels and format metadata", () => {
  const formats = [
    {
      label: "CVE list",
      value: "cve-list",
      accept: ".txt",
      detail: "One CVE per line.",
    },
    {
      label: "Trivy JSON",
      value: "trivy-json",
      accept: ".json",
      detail: "Trivy output.",
    },
  ] as const

  assert.equal(formatDisplayType("generic-occurrence-csv"), "generic occurrence csv")
  assert.equal(formatExpectedFields("trivy-json"), "Results[].Vulnerabilities[]")
  assert.equal(formatExpectedFields("cyclonedx-json"), "components, vulnerabilities")
  assert.equal(formatExpectedFields("generic-occurrence-csv"), "cve_id or equivalent supported CVE field")
  assert.equal(formatExpectedFields("nessus-xml"), "ReportHost, ReportItem CVE data")
  assert.equal(formatExpectedFields("openvas-xml"), "result CVE data")
  assert.equal(formatExpectedFields("unknown"), "Supported Workbench import fields")
  assert.equal(selectedFormat(formats, "trivy-json")?.label, "Trivy JSON")
  assert.equal(selectedFormat(formats, "unknown"), undefined)
})

test("import formats preserve exact supported input keys", () => {
  assert.deepEqual(
    workbenchImportFormats.map((format) => format.value),
    [
      "cve-list",
      "generic-occurrence-csv",
      "trivy-json",
      "grype-json",
      "cyclonedx-json",
      "spdx-json",
      "dependency-check-json",
      "github-alerts-json",
      "nessus-xml",
      "openvas-xml",
    ],
  )
  assert.equal(SUPPORTED_IMPORT_FORMATS.length, 10)
  const unsupported = ["osv-json", "ghsa-json", "sarif", "snyk-csv"]
  assert.equal(
    SUPPORTED_IMPORT_FORMATS.some((format) =>
      unsupported.includes(format.inputType),
    ),
    false,
  )
  assert.match(
    SUPPORTED_IMPORT_FORMATS.find(
      (format) => format.inputType === "cyclonedx-json",
    )?.notes.join(" ") ?? "",
    /without vulnerabilities is not sufficient/,
  )
  assert.match(
    SUPPORTED_IMPORT_FORMATS.find(
      (format) => format.inputType === "nessus-xml",
    )?.notes.join(" ") ?? "",
    /does not scan networks/,
  )
})

test("import model derives upload progress and safe file labels", () => {
  assert.equal(formatDateTime(null), "Not recorded")
  assert.equal(formatDateTime("not-a-date"), "Not recorded")
  assert.notEqual(formatDateTime("2026-05-10T10:00:00Z"), "Not recorded")
  assert.equal(fileSizeLabel(null), "No file selected")
  assert.equal(fileSizeLabel({ size: 12 } as File), "12 B")
  assert.equal(fileSizeLabel({ size: 2048 } as File), "2.0 KB")
  assert.equal(fileSizeLabel({ size: 2 * 1024 * 1024 } as File), "2.0 MB")
  assert.equal(
    uploadProgress({
      assetContextFile: null,
      file: null,
      inputType: "",
      vexFile: null,
    }),
    20,
  )
  assert.equal(
    uploadProgress({
      assetContextFile: {} as File,
      file: {} as File,
      inputType: "cve-list",
      providerSnapshotFile: "snapshot.json",
      vexFile: {} as File,
    }),
    100,
  )
  assert.equal(
    runFileLabel({
      input_type: "cve-list",
      summary_json: { input_upload: { filename: "findings.txt" } },
    }),
    "findings.txt",
  )
})

test("import model redacts path-like metadata rows from detail display", () => {
  assert.deepEqual(metadataRows(null), [])
  assert.deepEqual(
    metadataRows({ filename: "input.csv", source_path: "/tmp/input.csv" }),
    [["filename", "input.csv"]],
  )
})

test("import model selects readable failure causes", () => {
  assert.equal(failedRunCause(null, null), "No failure detail available.")
  assert.equal(failedRunCause({} as never, {} as never), "No failure detail available.")
  assert.equal(
    failedRunCause(
      { error_message: "Run level error" } as never,
      { error_json: { message: "Summary message" } } as never,
    ),
    "Run level error",
  )
  assert.equal(
    failedRunCause(null, { error_json: { error: "Parser error" } } as never),
    "Parser error",
  )
  assert.equal(
    failedRunCause(null, { error_json: { last_error: "Last parser error" } } as never),
    "Last parser error",
  )
  assert.equal(
    failedRunCause(null, {
      error_json: {
        analysis_error: { message: "Parser rejected the source file." },
      },
    } as never),
    "Parser rejected the source file.",
  )
  assert.equal(jsonPreview({ message: "failed" }), '{\n  "message": "failed"\n}')
})

test("import model maps run statuses to Workbench badge tones", () => {
  assert.equal(runTone("succeeded"), "success")
  assert.equal(runTone("completed"), "success")
  assert.equal(runTone("completed_with_errors"), "warning")
  assert.equal(runTone("failed"), "critical")
  assert.equal(runTone("cancelled"), "critical")
  assert.equal(runTone("pending"), "neutral")
})

test("import run timeline only includes evidence-backed events", () => {
  const runningSummary = {
    filename: null,
    finished_at: null,
    id: "run-1",
    input_type: "cve-list",
    input_upload: {},
    parse_errors: [],
    project_id: "project-1",
    started_at: "2026-05-10T10:00:00Z",
    status: "running",
  } as const

  assert.deepEqual(importRunTimelineItems(null, runningSummary as never), [
    "Import started",
  ])

  const terminalWithoutParserEvidence = {
    filename: null,
    finished_at: "2026-05-10T10:05:00Z",
    id: "run-empty",
    input_type: "cve-list",
    input_upload: {},
    project_id: "project-1",
    started_at: "2026-05-10T10:00:00Z",
    status: "succeeded",
  } as const
  assert.deepEqual(
    importRunTimelineItems(null, terminalWithoutParserEvidence as never),
    ["Import started", "Import completed"],
  )

  const parserErrorSummary = {
    ...runningSummary,
    filename: "broken.txt",
    finished_at: "2026-05-10T10:05:00Z",
    parse_errors: [{ message: "Invalid row" }],
    status: "failed",
  } as const
  assert.deepEqual(importRunTimelineItems(null, parserErrorSummary as never), [
    "Import started",
    "File uploaded",
    "Parser diagnostics recorded",
    "Import completed",
  ])

  const completedSummary = {
    ...runningSummary,
    created_findings: 0,
    filename: "findings.txt",
    finished_at: "2026-05-10T10:05:00Z",
    ignored_lines: 0,
    input_upload: { original_filename: "findings.txt" },
    status: "succeeded",
    updated_findings: 0,
  } as const
  const completedItems = importRunTimelineItems(null, completedSummary as never)
  assert.deepEqual(completedItems, [
    "Import started",
    "File uploaded",
    "Data parsed",
    "Import completed",
  ])
  assert.equal(completedItems.includes("Optional context applied"), false)
  assert.equal(completedItems.includes("Evidence recorded"), false)

  const contextualSummary = {
    ...completedSummary,
    created_findings: 2,
    provider_snapshot_id: "provider-snapshot-1",
    summary_json: {
      asset_context_upload: { original_filename: "assets.csv" },
      attack_source: "local-curated",
      provider_snapshot_file: "snapshot.json",
    },
  } as const
  assert.deepEqual(importRunTimelineItems(null, contextualSummary as never), [
    "Import started",
    "File uploaded",
    "Data parsed",
    "Provider data applied",
    "Optional context applied",
    "Findings created or updated",
    "Import completed",
  ])
})

test("active imports exports do not expose the legacy all-in-one wizard path", () => {
  const sectionsSource = readFileSync(
    new URL("../src/components/imports/ImportsWorkbenchSections.tsx", import.meta.url),
    "utf8",
  )
  const newImportRouteSource = readFileSync(
    new URL("../src/components/imports/NewImportRoute.tsx", import.meta.url),
    "utf8",
  )
  const importsHomeSource = readFileSync(
    new URL("../src/components/imports/ImportsHomeRoute.tsx", import.meta.url),
    "utf8",
  )
  const legacyAllInOneFiles = [
    "../src/components/imports/ImportWizardSteps.tsx",
    "../src/components/imports/ImportsWorkbenchHero.tsx",
    "../src/components/imports/ImportsWorkbenchRunDetail.tsx",
    "../src/components/imports/ImportsWorkbenchSupportedFormats.tsx",
    "../src/components/imports/ImportsWorkbenchWizard.tsx",
  ]

  assert.doesNotMatch(sectionsSource, /ImportHero/)
  assert.doesNotMatch(sectionsSource, /ImportWizard/)
  assert.doesNotMatch(sectionsSource, /ImportResult/)
  assert.doesNotMatch(sectionsSource, /export \{ RunDetail \}/)
  assert.doesNotMatch(sectionsSource, /export \{ SupportedFormats \}/)
  assert.match(importsHomeSource, /runTone\(lastRun\.status\)/)
  assert.doesNotMatch(newImportRouteSource, /Import result/)
  for (const file of legacyAllInOneFiles) {
    assert.equal(existsSync(new URL(file, import.meta.url)), false)
  }
})

test("import model summarizes optional overlays", () => {
  assert.equal(hasOptionalContext(defaultImportWizardState), false)
  assert.deepEqual(optionalContextLabels(defaultImportWizardState), [])
  const wizard = {
    ...defaultImportWizardState,
    assetContextFile: {} as File,
    attackSource: "local-curated" as const,
    lockedProviderData: true,
    providerSnapshotFile: "snapshot.json",
    vexFile: {} as File,
  }
  assert.equal(hasOptionalContext(wizard), true)
  assert.deepEqual(optionalContextLabels(wizard), [
    "Asset context CSV",
    "VEX sidecar",
    "Provider snapshot",
    "Locked provider data",
    "Reviewed ATT&CK mapping",
  ])
})

test("import upload payload includes provider and ATT&CK options", () => {
  const importFile = {} as File
  const assetContextFile = {} as File
  const vexFile = {} as File
  const payload = buildImportUploadFormData({
    importWizard: {
      ...defaultImportWizardState,
      attackMappingFile: " ctid-map.json ",
      attackSource: "ctid-json",
      attackTechniqueMetadataFile: " techniques.json ",
      inputType: "cyclonedx-json",
      lockedProviderData: true,
      providerSnapshotFile: " provider-snapshot.json ",
    },
    selectedAssetContextFile: assetContextFile,
    selectedFile: importFile,
    selectedVexFile: vexFile,
  })

  assert.equal(payload.attack_mapping_file, "ctid-map.json")
  assert.equal(payload.attack_source, "ctid-json")
  assert.equal(payload.attack_technique_metadata_file, "techniques.json")
  assert.equal(payload.asset_context_file, assetContextFile)
  assert.equal(payload.file, importFile)
  assert.equal(payload.input_type, "cyclonedx-json")
  assert.equal(payload.locked_provider_data, true)
  assert.equal(payload.provider_snapshot_file, "provider-snapshot.json")
  assert.equal(payload.vex_file, vexFile)
})

test("import upload payload omits empty optional file-name fields", () => {
  const importFile = {} as File
  const payload = buildImportUploadFormData({
    importWizard: {
      ...defaultImportWizardState,
      attackMappingFile: " ",
      attackSource: "none",
      attackTechniqueMetadataFile: "",
      inputType: "cve-list",
      providerSnapshotFile: "",
    },
    selectedAssetContextFile: null,
    selectedFile: importFile,
    selectedVexFile: null,
  })

  assert.deepEqual(payload, {
    attack_source: "none",
    file: importFile,
    input_type: "cve-list",
    locked_provider_data: false,
  })
})

test("import upload payload omits ATT&CK filenames when ATT&CK source is none", () => {
  const importFile = {} as File
  const payload = buildImportUploadFormData({
    importWizard: {
      ...defaultImportWizardState,
      attackMappingFile: "stale-map.json",
      attackSource: "none",
      attackTechniqueMetadataFile: "stale-techniques.json",
      inputType: "cve-list",
    },
    selectedAssetContextFile: null,
    selectedFile: importFile,
    selectedVexFile: null,
  })

  assert.equal(payload.attack_mapping_file, undefined)
  assert.equal(payload.attack_technique_metadata_file, undefined)
  assert.equal(payload.attack_source, "none")
})

test("demo provider snapshot preset enables deterministic replay", () => {
  const state = withDemoProviderSnapshot({
    ...defaultImportWizardState,
    file: {} as File,
    providerSnapshotFile: "",
  })

  assert.equal(state.lockedProviderData, true)
  assert.equal(state.providerSnapshotFile, demoProviderSnapshotFile)
})

test("import submit stays disabled until project and source file are ready", () => {
  const readyWizard = {
    ...defaultImportWizardState,
    file: { name: "findings.txt" } as File,
    inputType: "cve-list" as const,
  }

  assert.equal(
    importSubmitDisabled({
      importLoading: false,
      projectListLoading: false,
      projectCount: 1,
      selectedProjectId: "project-1",
      wizard: readyWizard,
    }),
    false,
  )
  assert.equal(
    importSubmitDisabled({
      importLoading: false,
      projectListLoading: false,
      projectCount: 1,
      selectedProjectId: "",
      wizard: readyWizard,
    }),
    true,
  )
  assert.equal(
    importSubmitDisabled({
      importLoading: false,
      projectListLoading: false,
      projectCount: 1,
      selectedProjectId: "project-1",
      wizard: {
        ...defaultImportWizardState,
        inputType: "cve-list",
      },
    }),
    true,
  )
  assert.equal(
    importSubmitDisabled({
      importLoading: true,
      projectListLoading: false,
      projectCount: 1,
      selectedProjectId: "project-1",
      wizard: readyWizard,
    }),
    true,
  )
})

test("readiness model blocks required fields and allows optional context", () => {
  const missingChecks = buildImportReadinessChecks({
    evidenceFile: null,
    inputType: "",
    parserPreview: initialParserPreview(),
    projectId: "",
    providerAvailable: true,
  })
  assert.equal(
    missingChecks.some((check) => check.status === "missing"),
    true,
  )
  const readyChecks = buildImportReadinessChecks({
    evidenceFile: { name: "findings.txt" } as File,
    inputType: "cve-list",
    parserPreview: {
      ...initialParserPreview(),
      state: "passed",
    },
    projectId: "project-1",
    providerAvailable: true,
  })
  assert.equal(
    readyChecks
      .filter((check) => ["asset-context", "vex", "attack-context"].includes(check.id))
      .every((check) => check.status === "optional"),
    true,
  )
  assert.equal(readinessBlocksImport(missingChecks), true)
  assert.equal(readinessBlocksImport(readyChecks), false)
})

test("readiness model blocks parser preview until the file check has passed", () => {
  function parserPreviewReadiness(state: ParserPreview["state"]) {
    const parserPreview: ParserPreview = {
      ...initialParserPreview(),
      state,
      errors: state === "error" ? ["Invalid JSON."] : [],
      warnings: state === "warning" ? ["Full parser results will be available after import."] : [],
    }
    const checks = buildImportReadinessChecks({
      evidenceFile: new File(["CVE-2024-3094"], "findings.txt", {
        type: "text/plain",
      }),
      inputType: "cve-list",
      parserPreview,
      projectId: "project-1",
      providerAvailable: true,
    })
    return {
      blocksImport: readinessBlocksImport(checks),
      status: checks.find((check) => check.id === "parser-preview")?.status,
    }
  }

  assert.deepEqual(parserPreviewReadiness("not-started"), {
    blocksImport: true,
    status: "pending",
  })
  assert.deepEqual(parserPreviewReadiness("checking"), {
    blocksImport: true,
    status: "pending",
  })
  assert.deepEqual(parserPreviewReadiness("error"), {
    blocksImport: true,
    status: "error",
  })
  assert.deepEqual(parserPreviewReadiness("warning"), {
    blocksImport: false,
    status: "warning",
  })
  assert.deepEqual(parserPreviewReadiness("passed"), {
    blocksImport: false,
    status: "passed",
  })
})

test("parser preview validates supported shallow input states", async () => {
  assert.deepEqual(await buildParserPreview(null, "cve-list"), initialParserPreview())
  assert.deepEqual(await buildParserPreview(new File([""], "input.txt"), "unknown"), initialParserPreview())
  assert.deepEqual(getAcceptedMimeTypes("unknown"), [])
  assert.equal(acceptedFileInputValue("unknown"), "")
  assert.equal(fileMatchesAcceptedExtension(null, "cve-list"), false)
  assert.equal(fileMatchesAcceptedExtension(new File([""], "input.json"), "cve-list"), false)

  const cvePreview = await buildParserPreview(
    new File(["CVE-2024-3094\nnot-a-cve"], "findings.txt", { type: "text/plain" }),
    "cve-list",
  )
  assert.equal(cvePreview.state, "passed")
  assert.equal(cvePreview.candidateRows, 1)
  assert.equal(cvePreview.ignoredRows, 1)
  assert.deepEqual(cvePreview.requiredFieldsFound, ["CVE identifier"])
  assert.match(cvePreview.warnings.join(" "), /do not look like CVE identifiers/)

  const emptyCvePreview = await buildParserPreview(
    new File(["not-a-cve"], "findings.csv", { type: "text/csv" }),
    "cve-list",
  )
  assert.equal(emptyCvePreview.state, "error")
  assert.deepEqual(emptyCvePreview.missingRequiredFields, ["CVE identifier"])

  const csvPreview = await buildParserPreview(
    new File(["CVE_ID,component\nCVE-2024-3094,xz\n"], "occurrences.csv", {
      type: "text/csv",
    }),
    "generic-occurrence-csv",
  )
  assert.equal(csvPreview.state, "passed")
  assert.equal(csvPreview.candidateRows, 1)
  assert.deepEqual(csvPreview.requiredFieldsFound, ["CVE column"])

  const missingHeaderPreview = await buildParserPreview(
    new File(["component\nxz"], "occurrences.csv", { type: "text/csv" }),
    "generic-occurrence-csv",
  )
  assert.equal(missingHeaderPreview.state, "error")
  assert.deepEqual(missingHeaderPreview.missingRequiredFields, ["CVE column"])
  assert.match(missingHeaderPreview.errors.join(" "), /cve_id/)

  const validJsonPreview = await buildParserPreview(
    new File([JSON.stringify({ Results: [] })], "trivy.json", {
      type: "application/json",
    }),
    "trivy-json",
  )
  assert.equal(validJsonPreview.state, "passed")
  assert.match(validJsonPreview.warnings.join(" "), /after import/)

  const invalidJsonPreview = await buildParserPreview(
    new File(["{"], "trivy.json", { type: "application/json" }),
    "trivy-json",
  )
  assert.equal(invalidJsonPreview.state, "error")
  assert.deepEqual(invalidJsonPreview.errors, ["Invalid JSON."])

  const xmlPreview = await buildParserPreview(
    new File(["<NessusClientData_v2 />"], "scan.nessus", {
      type: "application/xml",
    }),
    "nessus-xml",
  )
  assert.equal(xmlPreview.state, "passed")
  assert.match(xmlPreview.warnings.join(" "), /Full parser validation/)
})
