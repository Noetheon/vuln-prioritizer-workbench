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
  runLockedProviderData,
  runTone,
  selectedFormat,
  uploadProgress,
} from "../src/components/imports/imports-workbench-model.ts"
import {
  optionalContextReadiness,
  readinessCopyForStep,
  validateAssetContextCsvFile,
  validateVexJsonFile,
} from "../src/components/imports/new-import-route-state.ts"
import {
  defaultImportWizardState,
  demoProviderSnapshotFile,
  withDemoProviderSnapshot,
} from "../src/lib/app-defaults.ts"
import {
  acceptedFileInputValue,
  buildImportReadinessChecks,
  buildParserPreview,
  fileMatchesAcceptedExtension,
  getAcceptedMimeTypes,
  importFormatFromCapability,
  initialParserPreview,
  readinessBlocksImport,
  type ParserPreview,
} from "../src/lib/import-format-metadata.ts"
import type { ImportFormatCapabilityPublic } from "../src/api-client"
import { buildImportUploadFormData } from "../src/workbench/import-upload-payload.ts"

const TEST_IMPORT_CAPABILITIES: ImportFormatCapabilityPublic[] = [
  {
    accepted_mime_types: ["text/plain", "text/csv"],
    best_for: "Quick lists of already-known CVEs.",
    category: "simple",
    category_label: "Simple inputs",
    context_support: "cve-only",
    example_snippet: "CVE-2024-3094",
    expected_shape: "Plain text or CSV with one CVE identifier per line.",
    extensions: [".txt", ".csv"],
    input_type: "cve-list",
    label: "CVE list",
    minimum_fields: ["One CVE identifier per line or a CVE column"],
    notes: ["Use this for quick supplied CVE lists without asset context."],
    optional_fields: [],
    short_description: "Plain text or CSV with one CVE identifier per line.",
  },
  {
    accepted_mime_types: ["text/csv"],
    best_for: "Manual vulnerability backlog or occurrence lists.",
    category: "simple",
    category_label: "Simple inputs",
    context_support: "asset-context-capable",
    example_snippet: "cve_id,component_name\nCVE-2024-3094,xz",
    expected_shape: "CSV with CVE identifiers and optional asset or component context.",
    extensions: [".csv"],
    input_type: "generic-occurrence-csv",
    label: "Generic occurrence CSV",
    minimum_fields: ["cve_id or equivalent supported CVE field"],
    notes: ["Asset context can improve prioritization and explanations."],
    optional_fields: ["component_name"],
    short_description: "CSV with CVE identifiers and optional asset or component context.",
  },
  {
    accepted_mime_types: ["application/json"],
    best_for: "Container and filesystem exports from Trivy.",
    category: "scanner",
    category_label: "Scanner exports",
    context_support: "component-context",
    example_snippet: "{\"Results\":[]}",
    expected_shape: "Trivy vulnerability report JSON.",
    extensions: [".json"],
    input_type: "trivy-json",
    label: "Trivy JSON",
    minimum_fields: ["Results[].Vulnerabilities[]"],
    notes: ["Use the JSON report exported by Trivy."],
    optional_fields: ["PkgName"],
    short_description: "Trivy vulnerability export.",
  },
  {
    accepted_mime_types: ["application/json"],
    best_for: "Container and SBOM exports from Grype.",
    category: "scanner",
    category_label: "Scanner exports",
    context_support: "component-context",
    example_snippet: "{\"matches\":[]}",
    expected_shape: "Grype vulnerability report JSON.",
    extensions: [".json"],
    input_type: "grype-json",
    label: "Grype JSON",
    minimum_fields: ["matches[] vulnerability data"],
    notes: ["Use the JSON report exported by Grype."],
    optional_fields: ["artifact"],
    short_description: "Grype vulnerability export.",
  },
  {
    accepted_mime_types: ["application/json"],
    best_for: "Software inventory with vulnerability references.",
    category: "sbom",
    category_label: "SBOM / dependency data",
    context_support: "component-vulnerability-context",
    example_snippet: "{\"bomFormat\":\"CycloneDX\"}",
    expected_shape: "CycloneDX components plus vulnerability references.",
    extensions: [".json"],
    input_type: "cyclonedx-json",
    label: "CycloneDX SBOM JSON",
    minimum_fields: ["components", "vulnerabilities"],
    notes: ["Plain SBOM-only BOM without vulnerabilities is not sufficient."],
    optional_fields: ["bom-ref"],
    short_description: "CycloneDX SBOM plus vulnerabilities.",
  },
  {
    accepted_mime_types: ["application/json"],
    best_for: "SPDX package inventory with vulnerability references where supported.",
    category: "sbom",
    category_label: "SBOM / dependency data",
    context_support: "component-context",
    example_snippet: "{\"spdxVersion\":\"SPDX-2.3\"}",
    expected_shape: "SPDX JSON package data.",
    extensions: [".json"],
    input_type: "spdx-json",
    label: "SPDX SBOM JSON",
    minimum_fields: ["packages"],
    notes: ["Package data is parsed locally from supplied SPDX JSON."],
    optional_fields: ["externalRefs"],
    short_description: "SPDX JSON package data.",
  },
  {
    accepted_mime_types: ["application/json"],
    best_for: "OWASP Dependency-Check output.",
    category: "scanner",
    category_label: "Scanner exports",
    context_support: "component-context",
    example_snippet: "{\"dependencies\":[]}",
    expected_shape: "OWASP Dependency-Check JSON report.",
    extensions: [".json"],
    input_type: "dependency-check-json",
    label: "Dependency-Check JSON",
    minimum_fields: ["dependencies[].vulnerabilities[]"],
    notes: ["Use the JSON report exported by OWASP Dependency-Check."],
    optional_fields: ["packages"],
    short_description: "OWASP Dependency-Check JSON report.",
  },
  {
    accepted_mime_types: ["application/json"],
    best_for: "Pinned GitHub security or dependency alert evidence.",
    category: "scanner",
    category_label: "Scanner exports",
    context_support: "component-context",
    example_snippet: "[]",
    expected_shape: "Pinned GitHub alert export shape.",
    extensions: [".json"],
    input_type: "github-alerts-json",
    label: "GitHub alerts JSON",
    minimum_fields: ["alert vulnerability records"],
    notes: ["Use the pinned JSON export shape supported by the backend."],
    optional_fields: ["dependency"],
    short_description: "Pinned GitHub alert JSON export shape.",
  },
  {
    accepted_mime_types: ["application/xml", "text/xml"],
    best_for: "Network tool export evidence supplied as local XML.",
    category: "network",
    category_label: "Network scanner exports",
    context_support: "partial-occurrence-context",
    example_snippet: "<NessusClientData_v2 />",
    expected_shape: "Nessus export with ReportHost / ReportItem CVE data.",
    extensions: [".nessus", ".xml"],
    input_type: "nessus-xml",
    label: "Nessus XML",
    minimum_fields: ["ReportHost", "ReportItem CVE data"],
    notes: ["Parsed locally from supplied exports; the Workbench does not scan networks."],
    optional_fields: ["plugin_output"],
    short_description: "Nessus XML export parsed locally.",
  },
  {
    accepted_mime_types: ["application/xml", "text/xml"],
    best_for: "OpenVAS-style result evidence supplied as local XML.",
    category: "network",
    category_label: "Network scanner exports",
    context_support: "partial-occurrence-context",
    example_snippet: "<report />",
    expected_shape: "OpenVAS result CVE data.",
    extensions: [".xml"],
    input_type: "openvas-xml",
    label: "OpenVAS XML",
    minimum_fields: ["result CVE data"],
    notes: ["Parsed locally from supplied exports; the Workbench does not scan networks."],
    optional_fields: ["host"],
    short_description: "OpenVAS XML export parsed locally.",
  },
]

const TEST_SUPPORTED_FORMATS = TEST_IMPORT_CAPABILITIES.map(importFormatFromCapability)

test("import model derives display labels and format metadata", () => {
  assert.equal(formatDisplayType("generic-occurrence-csv"), "generic occurrence csv")
  assert.equal(formatExpectedFields(TEST_SUPPORTED_FORMATS, "trivy-json"), "Results[].Vulnerabilities[]")
  assert.equal(formatExpectedFields(TEST_SUPPORTED_FORMATS, "cyclonedx-json"), "components, vulnerabilities")
  assert.equal(formatExpectedFields(TEST_SUPPORTED_FORMATS, "generic-occurrence-csv"), "cve_id or equivalent supported CVE field")
  assert.equal(formatExpectedFields(TEST_SUPPORTED_FORMATS, "nessus-xml"), "ReportHost, ReportItem CVE data")
  assert.equal(formatExpectedFields(TEST_SUPPORTED_FORMATS, "openvas-xml"), "result CVE data")
  assert.equal(formatExpectedFields(TEST_SUPPORTED_FORMATS, "unknown"), "Supported Workbench import fields")
  assert.equal(selectedFormat(TEST_SUPPORTED_FORMATS, "trivy-json")?.label, "Trivy JSON")
  assert.equal(selectedFormat(TEST_SUPPORTED_FORMATS, "unknown"), undefined)
})

test("import formats preserve exact supported input keys", () => {
  const expectedInputTypes = [
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
  ]

  assert.deepEqual(
    TEST_SUPPORTED_FORMATS.map((format) => format.inputType),
    expectedInputTypes,
  )
  assert.equal(TEST_SUPPORTED_FORMATS.length, 10)
  const unsupported = ["osv-json", "ghsa-json", "sarif", "snyk-csv"]
  assert.equal(
    TEST_SUPPORTED_FORMATS.some((format) =>
      unsupported.includes(format.inputType),
    ),
    false,
  )
  assert.match(
    TEST_SUPPORTED_FORMATS.find(
      (format) => format.inputType === "cyclonedx-json",
    )?.notes.join(" ") ?? "",
    /without vulnerabilities is not sufficient/,
  )
  assert.equal(
    TEST_SUPPORTED_FORMATS.find(
      (format) => format.inputType === "cyclonedx-json",
    )?.contextSupport,
    "component-vulnerability-context",
  )
  assert.match(
    TEST_SUPPORTED_FORMATS.find(
      (format) => format.inputType === "nessus-xml",
    )?.notes.join(" ") ?? "",
    /does not scan networks/,
  )
})

test("import format catalog drives active upload choices and payload input types", () => {
  assert.deepEqual(
    TEST_SUPPORTED_FORMATS.map((format) => acceptedFileInputValue(format)),
    TEST_SUPPORTED_FORMATS.map((format) =>
      [...format.extensions, ...format.acceptedMimeTypes].join(","),
    ),
  )

  for (const format of TEST_SUPPORTED_FORMATS) {
    const selectedFile = {} as File
    const payload = buildImportUploadFormData({
      importWizard: {
        ...defaultImportWizardState,
        inputType: format.inputType,
      },
      selectedAssetContextFile: null,
      selectedFile,
      selectedVexFile: null,
    })

    assert.equal(payload.file, selectedFile)
    assert.equal(payload.input_type, format.inputType)
  }
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
      uploads: { input: { original_filename: "findings.txt" } },
    }),
    "findings.txt",
  )
  assert.equal(
    runFileLabel({
      input_type: "cve-list",
      uploads: { input: { filename: "raw-upload.txt" } },
    }),
    "raw-upload.txt",
  )
  assert.equal(
    runLockedProviderData({
      provider_snapshot: { locked: true },
    }),
    true,
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
      {} as never,
    ),
    "Run level error",
  )
  assert.equal(
    failedRunCause(null, { diagnostics_only: { message: "Hidden raw message" } } as never),
    "No failure detail available.",
  )
  assert.equal(
    failedRunCause(null, {
      diagnostics: {
        analysis_error: { message: "Parser error", stage: "analysis" },
      },
    } as never),
    "Parser error",
  )
  assert.equal(
    failedRunCause(null, {
      workflow: {
        diagnostics: {
          analysis_error: { message: "Last parser error", stage: "analysis" },
        },
      },
    } as never),
    "Last parser error",
  )
  assert.equal(
    failedRunCause(null, {
      diagnostics: {
        parse_errors: [{ message: "Parser rejected the source file." }],
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
    provider_snapshot: { file: "snapshot.json" },
    result: {
      attack_source: "local-curated",
    },
    uploads: {
      asset_context: { original_filename: "assets.csv" },
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
  const importsRouteSource = readFileSync(
    new URL("../src/workbench/routes/ImportsRoute.tsx", import.meta.url),
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
  assert.doesNotMatch(
    importsRouteSource,
    /catch \(caught\)[\s\S]*to: "\/imports\/runs\/\$runId"/,
  )
  assert.doesNotMatch(
    readFileSync(
      new URL("../src/components/imports/NewImportWizardSections.tsx", import.meta.url),
      "utf8",
    ),
    /Updates expected/,
  )
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

test("import upload payload normalizes empty ATT&CK source to none", () => {
  const importFile = {} as File
  const payload = buildImportUploadFormData({
    importWizard: {
      ...defaultImportWizardState,
      attackMappingFile: "stale-map.json",
      attackSource: "" as typeof defaultImportWizardState.attackSource,
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
      supportedFormats: TEST_SUPPORTED_FORMATS,
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
      supportedFormats: TEST_SUPPORTED_FORMATS,
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
      supportedFormats: TEST_SUPPORTED_FORMATS,
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
      supportedFormats: TEST_SUPPORTED_FORMATS,
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
    formats: TEST_SUPPORTED_FORMATS,
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
    formats: TEST_SUPPORTED_FORMATS,
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

test("optional context readiness validates selected asset and VEX files shallowly", async () => {
  const assetFile = new File(["owner,service\nplatform,payments"], "assets.csv", {
    type: "text/csv",
  })
  const emptyAssetFile = new File(["\nplatform,payments"], "assets.csv", {
    type: "text/csv",
  })
  const invalidVexFile = new File(["{"], "overlay.json", {
    type: "application/json",
  })
  const validVexFile = new File([JSON.stringify({ statements: [] })], "overlay.json", {
    type: "application/json",
  })

  const assetValidation = await validateAssetContextCsvFile(assetFile)
  const emptyAssetValidation = await validateAssetContextCsvFile(emptyAssetFile)
  const invalidVexValidation = await validateVexJsonFile(invalidVexFile)
  const validVexValidation = await validateVexJsonFile(validVexFile)

  assert.equal(assetValidation.status, "passed")
  assert.equal(emptyAssetValidation.status, "error")
  assert.match(emptyAssetValidation.message, /non-empty header row/)
  assert.equal(invalidVexValidation.status, "error")
  assert.match(invalidVexValidation.message, /Invalid VEX overlay/)
  assert.equal(validVexValidation.status, "passed")

  const pendingChecks = optionalContextReadiness({
    assetContextFile: assetFile,
    assetContextValidation: {
      fileKey: assetValidation.fileKey,
      message: "Checking asset context CSV.",
      status: "checking",
    },
    vexFile: null,
  })
  assert.equal(pendingChecks["asset-context"]?.status, "pending")
  assert.equal(readinessBlocksImport(Object.values(pendingChecks)), true)

  const invalidChecks = optionalContextReadiness({
    assetContextFile: null,
    vexFile: invalidVexFile,
    vexValidation: invalidVexValidation,
  })
  assert.equal(invalidChecks.vex?.status, "error")
  assert.equal(readinessBlocksImport(Object.values(invalidChecks)), true)

  const validChecks = optionalContextReadiness({
    assetContextFile: assetFile,
    assetContextValidation: assetValidation,
    vexFile: validVexFile,
    vexValidation: validVexValidation,
  })
  assert.equal(validChecks["asset-context"]?.status, "passed")
  assert.equal(validChecks.vex?.status, "passed")
  assert.equal(readinessBlocksImport(Object.values(validChecks)), false)

  const missingAttackMappingChecks = optionalContextReadiness({
    assetContextFile: null,
    attackMappingFile: "",
    attackSource: "local-curated",
    vexFile: null,
  })
  assert.equal(missingAttackMappingChecks["attack-context"]?.status, "error")
  assert.match(
    missingAttackMappingChecks["attack-context"]?.message ?? "",
    /Mapping file is required/,
  )
  assert.equal(
    readinessBlocksImport(Object.values(missingAttackMappingChecks)),
    true,
  )

  const validAttackMappingChecks = optionalContextReadiness({
    assetContextFile: null,
    attackMappingFile: "mapping.json",
    attackSource: "ctid-json",
    vexFile: null,
  })
  assert.equal(validAttackMappingChecks["attack-context"]?.status, "passed")
  assert.equal(readinessBlocksImport(Object.values(validAttackMappingChecks)), false)
})

test("readiness copy uses specific wizard states for context blockers", () => {
  const missingChecks = buildImportReadinessChecks({
    evidenceFile: null,
    formats: TEST_SUPPORTED_FORMATS,
    inputType: "",
    parserPreview: initialParserPreview(),
    projectId: "",
    providerAvailable: true,
  })
  const readyChecks = buildImportReadinessChecks({
    evidenceFile: new File(["cve_id\nCVE-2024-3094"], "findings.csv", {
      type: "text/csv",
    }),
    formats: TEST_SUPPORTED_FORMATS,
    inputType: "generic-occurrence-csv",
    parserPreview: {
      ...initialParserPreview(),
      state: "passed",
    },
    projectId: "project-1",
    providerAvailable: true,
  })
  const contextBlockedChecks = readyChecks.map(
    (check) =>
      optionalContextReadiness({
        attackMappingFile: "",
        attackSource: "ctid-json",
        assetContextFile: null,
        vexFile: null,
      })[check.id] ?? check,
  )

  assert.equal(readinessCopyForStep(1, missingChecks), "Needs input type")
  assert.equal(readinessCopyForStep(2, missingChecks), "Needs evidence file")
  assert.equal(readinessCopyForStep(2, readyChecks), "Can continue")
  assert.equal(readinessCopyForStep(3, readyChecks), "Can continue")
  assert.equal(readinessCopyForStep(3, contextBlockedChecks), "Needs context")
  assert.equal(readinessCopyForStep(4, contextBlockedChecks), "Needs context")
  assert.equal(readinessCopyForStep(4, readyChecks), "Ready to import")
  assert.equal(readinessCopyForStep(4, readyChecks, true), "Failed")
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
      formats: TEST_SUPPORTED_FORMATS,
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
  assert.deepEqual(await buildParserPreview(TEST_SUPPORTED_FORMATS, null, "cve-list"), initialParserPreview())
  assert.deepEqual(
    await buildParserPreview(TEST_SUPPORTED_FORMATS, new File([""], "input.txt"), "unknown"),
    initialParserPreview(),
  )
  assert.deepEqual(getAcceptedMimeTypes(TEST_SUPPORTED_FORMATS, "unknown"), [])
  assert.equal(acceptedFileInputValue(undefined), "")
  assert.equal(fileMatchesAcceptedExtension(TEST_SUPPORTED_FORMATS, null, "cve-list"), false)
  assert.equal(
    fileMatchesAcceptedExtension(TEST_SUPPORTED_FORMATS, new File([""], "input.json"), "cve-list"),
    false,
  )

  const cvePreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File(["CVE-2024-3094\nnot-a-cve"], "findings.txt", { type: "text/plain" }),
    "cve-list",
  )
  assert.equal(cvePreview.state, "passed")
  assert.equal(cvePreview.candidateRows, 1)
  assert.equal(cvePreview.ignoredRows, 1)
  assert.deepEqual(cvePreview.requiredFieldsFound, ["CVE identifier"])
  assert.match(cvePreview.warnings.join(" "), /do not look like CVE identifiers/)

  const emptyCvePreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File(["not-a-cve"], "findings.csv", { type: "text/csv" }),
    "cve-list",
  )
  assert.equal(emptyCvePreview.state, "error")
  assert.deepEqual(emptyCvePreview.missingRequiredFields, ["CVE identifier"])

  const csvPreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File(["CVE_ID,component\nCVE-2024-3094,xz\n"], "occurrences.csv", {
      type: "text/csv",
    }),
    "generic-occurrence-csv",
  )
  assert.equal(csvPreview.state, "passed")
  assert.equal(csvPreview.candidateRows, 1)
  assert.deepEqual(csvPreview.requiredFieldsFound, ["CVE column"])

  const missingHeaderPreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File(["component\nxz"], "occurrences.csv", { type: "text/csv" }),
    "generic-occurrence-csv",
  )
  assert.equal(missingHeaderPreview.state, "error")
  assert.deepEqual(missingHeaderPreview.missingRequiredFields, ["CVE column"])
  assert.match(missingHeaderPreview.errors.join(" "), /cve_id/)

  const validJsonPreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File([JSON.stringify({ Results: [] })], "trivy.json", {
      type: "application/json",
    }),
    "trivy-json",
  )
  assert.equal(validJsonPreview.state, "passed")
  assert.match(validJsonPreview.warnings.join(" "), /after import/)

  const invalidJsonPreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File(["{"], "trivy.json", { type: "application/json" }),
    "trivy-json",
  )
  assert.equal(invalidJsonPreview.state, "error")
  assert.deepEqual(invalidJsonPreview.errors, ["Invalid JSON."])

  const xmlPreview = await buildParserPreview(
    TEST_SUPPORTED_FORMATS,
    new File(["<NessusClientData_v2 />"], "scan.nessus", {
      type: "application/xml",
    }),
    "nessus-xml",
  )
  assert.equal(xmlPreview.state, "passed")
  assert.match(xmlPreview.warnings.join(" "), /Full parser validation/)
})
