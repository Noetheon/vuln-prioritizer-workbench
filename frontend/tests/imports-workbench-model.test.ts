import assert from "node:assert/strict"
import test from "node:test"

import {
  failedRunCause,
  formatDisplayType,
  formatExpectedFields,
  importSubmitDisabled,
  jsonPreview,
  metadataRows,
  runFileLabel,
  runTone,
  selectedFormat,
  uploadProgress,
} from "../src/components/imports/imports-workbench-model.ts"
import {
  defaultImportWizardState,
  demoProviderSnapshotFile,
  withDemoProviderSnapshot,
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
  assert.equal(formatExpectedFields("nessus-xml"), "Nessus ReportHost/ReportItem CVE data")
  assert.equal(selectedFormat(formats, "trivy-json")?.label, "Trivy JSON")
  assert.equal(selectedFormat(formats, "unknown")?.label, "CVE list")
})

test("import model derives upload progress and safe file labels", () => {
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
  assert.equal(runTone("completed_with_errors"), "warning")
  assert.equal(runTone("failed"), "critical")
  assert.equal(runTone("pending"), "neutral")
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
