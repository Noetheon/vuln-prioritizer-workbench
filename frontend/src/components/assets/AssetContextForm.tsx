import { ChevronDown, FileInput } from "lucide-react"
import type { FormEvent } from "react"
import type {
  AssetCriticality,
  AssetEnvironment,
  AssetExposure,
} from "../../api-client"
import { formatLabel as labelize } from "../../lib/ui-copy"
import { Button } from "../ui/button"
import { Input } from "../ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select"
import {
  VpwField,
  VpwFileInput,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "../vpw"
import {
  type AssetFormState,
  criticalityOptions,
  environmentOptions,
  exposureOptions,
} from "./asset-model"

export function AssetForm({
  busy = false,
  buttonLabel,
  disabled,
  error,
  form,
  formLabel,
  onChange,
  onSubmit,
}: {
  busy?: boolean
  buttonLabel: string
  disabled: boolean
  error: string
  form: AssetFormState
  formLabel: string
  onChange: (form: AssetFormState) => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
}) {
  const isEdit = formLabel.includes("Edit")
  const fieldPrefix = isEdit ? "edit-asset" : "create-asset"

  return (
    <form
      aria-label={formLabel}
      className="flex flex-col gap-4"
      onSubmit={onSubmit}
    >
      <VpwGrid columns={2}>
        <VpwField
          htmlFor={`${fieldPrefix}-asset-key`}
          label="Asset key"
          required
        >
          <Input
            aria-label={isEdit ? "Edit asset key" : "Asset key"}
            id={`${fieldPrefix}-asset-key`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, asset_key: event.target.value })
            }
            placeholder="app-prod-01"
            value={form.asset_key}
          />
        </VpwField>
        <VpwField
          htmlFor={`${fieldPrefix}-asset-name`}
          label="Asset name"
          required
        >
          <Input
            aria-label={isEdit ? "Edit asset name" : "Asset name"}
            id={`${fieldPrefix}-asset-name`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, name: event.target.value })
            }
            placeholder="Payments API"
            value={form.name}
          />
        </VpwField>
        <VpwField htmlFor={`${fieldPrefix}-owner`} label="Owner">
          <Input
            aria-label={isEdit ? "Edit owner" : "Owner"}
            id={`${fieldPrefix}-owner`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, owner: event.target.value })
            }
            placeholder="Platform security"
            value={form.owner}
          />
        </VpwField>
        <VpwField
          htmlFor={`${fieldPrefix}-business-service`}
          label="Business service"
        >
          <Input
            aria-label={isEdit ? "Edit business service" : "Business service"}
            id={`${fieldPrefix}-business-service`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, business_service: event.target.value })
            }
            placeholder="Checkout"
            value={form.business_service}
          />
        </VpwField>
        <VpwField
          className="lg:col-span-2"
          htmlFor={`${fieldPrefix}-target-ref`}
          label="Target ref"
        >
          <Input
            aria-label={isEdit ? "Edit target ref" : "Target ref"}
            id={`${fieldPrefix}-target-ref`}
            maxLength={512}
            onChange={(event) =>
              onChange({ ...form, target_ref: event.target.value })
            }
            placeholder="image:registry.example.com/payments-api"
            value={form.target_ref}
          />
        </VpwField>
        <VpwField label="Criticality">
          <Select
            onValueChange={(value) =>
              onChange({
                ...form,
                criticality: value as AssetCriticality,
              })
            }
            value={form.criticality}
          >
            <SelectTrigger
              aria-label={isEdit ? "Edit criticality" : "Criticality"}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {criticalityOptions.map((option) => (
                <SelectItem key={option} value={option}>
                  {labelize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </VpwField>
        <VpwField label="Environment">
          <Select
            onValueChange={(value) =>
              onChange({
                ...form,
                environment: value as AssetEnvironment,
              })
            }
            value={form.environment}
          >
            <SelectTrigger
              aria-label={isEdit ? "Edit environment" : "Environment"}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {environmentOptions.map((option) => (
                <SelectItem key={option} value={option}>
                  {labelize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </VpwField>
        <VpwField label="Exposure">
          <Select
            onValueChange={(value) =>
              onChange({
                ...form,
                exposure: value as AssetExposure,
              })
            }
            value={form.exposure}
          >
            <SelectTrigger aria-label={isEdit ? "Edit exposure" : "Exposure"}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {exposureOptions.map((option) => (
                <SelectItem key={option} value={option}>
                  {labelize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </VpwField>
      </VpwGrid>
      {error ? (
        <VpwStatusBanner title="Asset form needs attention" tone="critical">
          {error}
        </VpwStatusBanner>
      ) : null}
      <Button aria-busy={busy} disabled={disabled} type="submit">
        {buttonLabel}
      </Button>
    </form>
  )
}

export function AssetContextForms({
  activeProjectLabel,
  assetActionLoading,
  assetContextFile,
  createAsset,
  createError,
  createForm,
  importAssetContext,
  projectCount,
  setAssetContextFile,
  setCreateForm,
}: {
  activeProjectLabel: string
  assetActionLoading: boolean
  assetContextFile: File | null
  createAsset: (event: FormEvent<HTMLFormElement>) => void
  createError: string
  createForm: AssetFormState
  importAssetContext: (event: FormEvent<HTMLFormElement>) => void
  projectCount: number
  setAssetContextFile: (file: File | null) => void
  setCreateForm: (form: AssetFormState) => void
}) {
  return (
    <VpwGrid columns={2}>
      <div id="asset-context-import">
        <AssetContextImportPanel
          activeProjectLabel={activeProjectLabel}
          assetActionLoading={assetActionLoading}
          assetContextFile={assetContextFile}
          importAssetContext={importAssetContext}
          projectCount={projectCount}
          setAssetContextFile={setAssetContextFile}
        />
      </div>

      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          description="Create a single asset context record when a CSV import is not needed."
          eyebrow="Manual context"
          title="Create asset"
        />
        <AssetForm
          busy={assetActionLoading}
          buttonLabel="Create Asset"
          disabled={assetActionLoading || projectCount === 0}
          error={createError}
          form={createForm}
          formLabel="Create Asset form fields"
          onChange={setCreateForm}
          onSubmit={createAsset}
        />
      </VpwPanel>
    </VpwGrid>
  )
}

export function AssetContextImportForm({
  activeProjectLabel,
  assetActionLoading,
  assetContextFile,
  importAssetContext,
  projectCount,
  setAssetContextFile,
}: {
  activeProjectLabel: string
  assetActionLoading: boolean
  assetContextFile: File | null
  importAssetContext: (event: FormEvent<HTMLFormElement>) => void
  projectCount: number
  setAssetContextFile: (file: File | null) => void
}) {
  return (
    <div className="flex flex-col gap-4">
      <form
        aria-label="Import Asset Context form fields"
        className="flex flex-col gap-4"
        onSubmit={importAssetContext}
      >
        <VpwField
          description="Accepted CSV context can update target reference, owner, business service, environment, exposure and criticality."
          htmlFor="asset-context-csv"
          label="Asset context CSV"
        >
          <VpwFileInput
            accept=".csv,text/csv"
            file={assetContextFile}
            id="asset-context-csv"
            label="Asset context CSV"
            onFileChange={setAssetContextFile}
          />
        </VpwField>
        <Button
          aria-busy={assetActionLoading}
          disabled={
            assetActionLoading || projectCount === 0 || !assetContextFile
          }
          type="submit"
        >
          <FileInput aria-hidden="true" />
          Upload context
        </Button>
      </form>
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Selected file",
            value: assetContextFile?.name ?? "None selected",
          },
          {
            label: "Target project",
            value: activeProjectLabel,
          },
        ]}
      />
      <details className="group rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
          <span>
            <span className="vpw-label text-[var(--vpw-teal)]">
              Supported CSV context
            </span>
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              Use existing asset context fields only; scanner discovery is not
              part of this workflow.
            </span>
          </span>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-180"
          />
        </summary>
        <div className="border-t border-[var(--vpw-border-subtle)] px-5 py-4 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Include target ref or asset key plus any of owner, business service,
          environment, exposure and criticality. Blank optional fields leave the
          asset context local and editable.
        </div>
      </details>
    </div>
  )
}

function AssetContextImportPanel(
  props: Parameters<typeof AssetContextImportForm>[0],
) {
  return (
    <VpwPanel className="flex flex-col gap-4 p-5">
      <VpwSectionHeader
        description="Upload CSV context to update asset ownership, service, environment, exposure and criticality."
        eyebrow="Context intake"
        title="Import asset context"
      />
      <AssetContextImportForm {...props} />
    </VpwPanel>
  )
}
