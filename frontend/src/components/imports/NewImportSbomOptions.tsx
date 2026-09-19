import { Input } from "@/components/ui/input"
import { VpwField } from "@/components/vpw"
import type { ImportsWorkbenchProps } from "./imports-workbench-model"

export function SbomScanOptions({
  importWizard,
  onSbomScannerChange,
  onSbomTargetRefChange,
  onSbomDbUpdateChange,
}: Pick<
  ImportsWorkbenchProps,
  | "importWizard"
  | "onSbomScannerChange"
  | "onSbomTargetRefChange"
  | "onSbomDbUpdateChange"
>) {
  if (!["cyclonedx-json", "spdx-json"].includes(importWizard.inputType))
    return null
  const scanEnabled = importWizard.sbomScanner === "grype"
  return (
    <section className="grid gap-4 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-4">
      <label className="flex items-start gap-3 text-sm" htmlFor="sbom-scan">
        <Input
          checked={scanEnabled}
          className="mt-1 size-4 min-w-4 shrink-0 p-0 accent-[var(--vpw-blue)]"
          id="sbom-scan"
          onChange={(event) =>
            onSbomScannerChange(event.target.checked ? "grype" : "none")
          }
          type="checkbox"
        />
        <span>
          <span className="block font-semibold">Scan SBOM with Grype</span>
          <span className="mt-1 block text-xs leading-5 text-[var(--vpw-text-secondary)]">
            Match the uploaded component inventory against a local vulnerability
            database, then prioritize the detected CVEs. Leave off to import
            vulnerability records already in the file.
          </span>
        </span>
      </label>
      {scanEnabled ? (
        <>
          <VpwField
            description="Use a stable application or image reference so later scans remain associated with the same subject."
            htmlFor="sbom-target-ref"
            label="SBOM subject"
          >
            <Input
              id="sbom-target-ref"
              maxLength={500}
              onChange={(event) => onSbomTargetRefChange(event.target.value)}
              placeholder="payments-service@1.2.0"
              required
              value={importWizard.sbomTargetRef ?? ""}
            />
          </VpwField>
          <label
            className="flex items-start gap-3 text-sm"
            htmlFor="sbom-db-update"
          >
            <Input
              checked={importWizard.sbomDbUpdate ?? true}
              className="mt-1 size-4 min-w-4 shrink-0 p-0 accent-[var(--vpw-blue)]"
              id="sbom-db-update"
              onChange={(event) => onSbomDbUpdateChange(event.target.checked)}
              type="checkbox"
            />
            <span>
              <span className="block font-medium">
                Allow vulnerability database updates
              </span>
              <span className="mt-1 block text-xs leading-5 text-[var(--vpw-text-secondary)]">
                Downloads database updates when needed. The SBOM stays on this
                Workbench server. Turn off to use the installed database without
                a network update.
              </span>
            </span>
          </label>
        </>
      ) : null}
    </section>
  )
}
