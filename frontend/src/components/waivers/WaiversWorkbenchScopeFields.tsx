import type { AssetPublic, FindingPublic } from "@/api-client"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { VpwField, VpwGrid } from "@/components/vpw"
import {
  findingScopeOptionLabel,
  scopeSuggestions,
} from "./waiver-scope-model"
import type { WaiversWorkbenchProps } from "./waivers-workbench-model"

// Radix Select items cannot use an empty value.
const NO_SCOPE = "none"

/**
 * Scope anchors of an acceptance. Findings and assets are chosen from the
 * project, not typed as UUIDs; CVE, asset key, and service suggest the
 * values the project already has.
 */
export function WaiverScopeFields({
  assets,
  findings,
  onFieldChange,
  waiverForm,
}: {
  assets: readonly AssetPublic[]
  findings: readonly FindingPublic[]
  onFieldChange: WaiversWorkbenchProps["onFieldChange"]
  waiverForm: WaiversWorkbenchProps["waiverForm"]
}) {
  const suggestions = scopeSuggestions(findings, assets)
  const chosenFindingListed = findings.some(
    (finding) => finding.id === waiverForm.findingId,
  )
  const chosenAssetListed = assets.some(
    (asset) => asset.id === waiverForm.assetId,
  )

  function chooseFinding(value: string) {
    const finding = findings.find((candidate) => candidate.id === value)
    onFieldChange("findingId", finding ? finding.id : "")
    if (finding && !waiverForm.cveId.trim()) {
      onFieldChange("cveId", finding.cve_id)
    }
  }

  return (
    <VpwGrid columns={2}>
      <VpwField
        className="lg:col-span-2"
        htmlFor="waiver-finding"
        label="Finding"
      >
        <Select
          onValueChange={chooseFinding}
          value={waiverForm.findingId || NO_SCOPE}
        >
          <SelectTrigger
            aria-label="Acceptance finding"
            className="w-full min-w-0"
            id="waiver-finding"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NO_SCOPE}>Any finding in the scope</SelectItem>
            {waiverForm.findingId && !chosenFindingListed ? (
              <SelectItem value={waiverForm.findingId}>
                Finding {waiverForm.findingId.slice(0, 8)}
              </SelectItem>
            ) : null}
            {findings.map((finding) => (
              <SelectItem key={finding.id} value={finding.id}>
                {findingScopeOptionLabel(finding)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </VpwField>
      <VpwField htmlFor="waiver-cve-id" label="CVE ID">
        <Input
          aria-label="Acceptance CVE ID"
          id="waiver-cve-id"
          list="waiver-cve-options"
          onChange={(event) => onFieldChange("cveId", event.target.value)}
          placeholder="CVE-2024-3094"
          value={waiverForm.cveId}
        />
        <datalist id="waiver-cve-options">
          {suggestions.cveIds.map((cveId) => (
            <option key={cveId} value={cveId} />
          ))}
        </datalist>
      </VpwField>
      <VpwField htmlFor="waiver-asset" label="Asset">
        <Select
          onValueChange={(value) =>
            onFieldChange("assetId", value === NO_SCOPE ? "" : value)
          }
          value={waiverForm.assetId || NO_SCOPE}
        >
          <SelectTrigger
            aria-label="Acceptance asset"
            className="w-full min-w-0"
            id="waiver-asset"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NO_SCOPE}>Any asset</SelectItem>
            {waiverForm.assetId && !chosenAssetListed ? (
              <SelectItem value={waiverForm.assetId}>
                Asset {waiverForm.assetId.slice(0, 8)}
              </SelectItem>
            ) : null}
            {assets.map((asset) => (
              <SelectItem key={asset.id} value={asset.id}>
                {asset.name === asset.asset_key
                  ? asset.name
                  : `${asset.name} (${asset.asset_key})`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </VpwField>
      <VpwField htmlFor="waiver-asset-key" label="Asset key">
        <Input
          aria-label="Acceptance asset key"
          id="waiver-asset-key"
          list="waiver-asset-key-options"
          onChange={(event) => onFieldChange("assetKey", event.target.value)}
          placeholder="payments-api"
          value={waiverForm.assetKey}
        />
        <datalist id="waiver-asset-key-options">
          {suggestions.assetKeys.map((assetKey) => (
            <option key={assetKey} value={assetKey} />
          ))}
        </datalist>
      </VpwField>
      <VpwField htmlFor="waiver-service" label="Service">
        <Input
          aria-label="Acceptance service"
          id="waiver-service"
          list="waiver-service-options"
          onChange={(event) => onFieldChange("service", event.target.value)}
          placeholder="checkout"
          value={waiverForm.service}
        />
        <datalist id="waiver-service-options">
          {suggestions.services.map((service) => (
            <option key={service} value={service} />
          ))}
        </datalist>
      </VpwField>
    </VpwGrid>
  )
}
