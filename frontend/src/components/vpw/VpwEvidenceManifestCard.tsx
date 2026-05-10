import { Download } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

import { VpwBadge } from "./VpwBadge"
import { VpwChecksum } from "./VpwChecksum"
import { VpwKeyValueList } from "./VpwKeyValueList"

export type VpwManifestFile = {
  path: string
  label?: string
}

export type VpwEvidenceManifestCardProps = {
  project: string
  runId: string
  generatedAt: string
  providerSources: string
  verificationStatus: string
  checksumStatus?: string
  className?: string
  demo?: boolean
  downloadDisabled?: boolean
  downloadLabel?: string
  files: readonly VpwManifestFile[]
  onDownload?: () => void
}

export function VpwEvidenceManifestCard({
  checksumStatus,
  className,
  demo = false,
  downloadDisabled = false,
  downloadLabel = "Download manifest",
  files,
  generatedAt,
  onDownload,
  project,
  providerSources,
  runId,
  verificationStatus,
}: VpwEvidenceManifestCardProps) {
  const checksumValue =
    checksumStatus ??
    (demo ? "Demo preview - not real checksums" : "Not available")
  const rows = [
    { label: "Project", value: project },
    { label: "Run ID", value: runId },
    { label: "Generated at", value: generatedAt },
    { label: "Provider sources", value: providerSources },
    { label: "Verification", value: verificationStatus },
  ]

  return (
    <Card className={cn("vpw-card py-0", className)}>
      <CardHeader className="pb-3 pt-6">
        <CardTitle className="text-lg">Evidence Manifest</CardTitle>
        <CardDescription>Audit trail and bundle integrity</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5 pb-6">
        <VpwKeyValueList columns={2} items={rows} />
        <VpwChecksum
          demo={demo}
          value={checksumValue}
          verified={
            !demo && verificationStatus.toLowerCase().includes("verified")
          }
        />
        <div>
          <p className="vpw-label">Included files</p>
          {files.length > 0 ? (
            <ul className="mt-2 flex flex-col gap-2 text-sm text-[var(--vpw-text-secondary)]">
              {files.map((file) => (
                <li
                  className="flex items-center justify-between gap-2"
                  key={file.path}
                >
                  <span className="truncate font-mono text-xs">
                    {file.path}
                  </span>
                  {file.label ? <VpwBadge>{file.label}</VpwBadge> : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-sm text-[var(--vpw-text-secondary)]">
              Generate reports to populate the manifest.
            </p>
          )}
        </div>
        <Button
          className="w-full"
          disabled={downloadDisabled}
          onClick={onDownload}
          type="button"
          variant="outline"
        >
          <Download aria-hidden="true" data-icon="inline-start" />
          {downloadLabel}
        </Button>
      </CardContent>
    </Card>
  )
}
