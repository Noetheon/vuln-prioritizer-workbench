import assert from "node:assert/strict"
import test from "node:test"

import {
  failedRunCause,
  formatDisplayType,
  formatExpectedFields,
  jsonPreview,
  metadataRows,
  runFileLabel,
  runTone,
  selectedFormat,
  uploadProgress,
} from "../src/components/imports/imports-workbench-model.ts"

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
