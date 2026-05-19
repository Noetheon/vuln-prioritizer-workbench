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
import { VpwField, VpwGrid, VpwStatusBanner } from "../vpw"
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
