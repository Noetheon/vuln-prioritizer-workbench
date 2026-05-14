import assert from "node:assert/strict"
import test from "node:test"

import {
  failedRunCause,
  fileSizeLabel,
  formatDateTime,
  formatDisplayType,
  formatExpectedFields,
  hasOptionalContext,
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
  assert.equal(formatExpectedFields("trivy-json"), "Trivy Results[].Vulnerabilities")
  assert.equal(formatExpectedFields("cyclonedx-json"), "CycloneDX components/vulnerabilities")
  assert.equal(formatExpectedFields("generic-occurrence-csv"), "cve_id plus optional asset/component columns")
  assert.equal(formatExpectedFields("nessus-xml"), "Nessus ReportHost/ReportItem CVE data")
  assert.equal(formatExpectedFields("openvas-xml"), "OpenVAS result CVE data")
  assert.equal(formatExpectedFields("unknown"), "Supported Workbench import fields")
  assert.equal(selectedFormat(formats, "trivy-json")?.label, "Trivy JSON")
  assert.equal(selectedFormat(formats, "unknown")?.label, "CVE list")
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
})

test("import model derives upload progress and safe file labels", () => {
  assert.equal(formatDateTime(null), "Not recorded")
  assert.equal(formatDateTime("not-a-date"), "Not recorded")
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
      providerSnapshotFile: "",
    },
    selectedAssetContextFile: null,
    selectedFile: importFile,
    selectedVexFile: null,
  })

  assert.deepEqual(payload, {
    attack_source: "none",
    file: importFile,
    input_type: defaultImportWizardState.inputType,
    locked_provider_data: false,
  })
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
    file: {} as File,
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
      wizard: defaultImportWizardState,
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
