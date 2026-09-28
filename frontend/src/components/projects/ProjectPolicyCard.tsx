import { useQuery, useQueryClient } from "@tanstack/react-query"
import { type ReactNode, useEffect, useId, useState } from "react"
import { ProjectsService } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { VpwBadge } from "@/components/vpw"
import { apiErrorMessage } from "@/lib/app-errors"
import {
  type PolicyFormErrors,
  type PolicyFormState,
  type SlaField,
  type ThresholdField,
  policyFormErrors,
  policyFormFromFields,
  policyFormsEqual,
  policySaveMessage,
  policyUpdateFromForm,
  slaFields,
  slaHoursHint,
} from "@/lib/project-policy-form"
import {
  invalidateProjectScopedWorkbenchQueries,
  workbenchQueryKeys,
} from "@/workbench/workbench-query-keys"

const priorityRows: readonly {
  cvss: ThresholdField
  epss: ThresholdField
  label: string
  rule: string
}[] = [
  {
    cvss: "critical_cvss_threshold",
    epss: "critical_epss_threshold",
    label: "Critical",
    rule: "KEV, or EPSS and CVSS both at or above",
  },
  {
    cvss: "high_cvss_threshold",
    epss: "high_epss_threshold",
    label: "High",
    rule: "EPSS or CVSS at or above",
  },
  {
    cvss: "medium_cvss_threshold",
    epss: "medium_epss_threshold",
    label: "Medium",
    rule: "EPSS or CVSS at or above",
  },
]

const slaLabels: Record<SlaField, string> = {
  critical: "Critical",
  high: "High",
  low: "Low",
  medium: "Medium",
}

export function ProjectPolicyCard({ projectId }: { projectId: string }) {
  const queryClient = useQueryClient()
  const idPrefix = useId()
  const policyQuery = useQuery({
    queryKey: workbenchQueryKeys.projectPolicy(projectId),
    queryFn: ({ signal }) =>
      ProjectsService.readProjectPolicy({ project_id: projectId }, { signal }),
    retry: false,
  })
  const policy = policyQuery.data
  const [form, setForm] = useState<PolicyFormState | null>(null)
  const [reason, setReason] = useState("")
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState("")
  const [error, setError] = useState("")

  useEffect(() => {
    if (policy) setForm(policyFormFromFields(policy))
  }, [policy])

  if (policyQuery.isError) {
    return (
      <PolicyCardFrame>
        <p className="text-sm text-[var(--vpw-red)]" role="alert">
          {apiErrorMessage("Priority policy unavailable", policyQuery.error)}
        </p>
      </PolicyCardFrame>
    )
  }
  if (!policy || !form) {
    return (
      <PolicyCardFrame>
        <p className="text-sm" role="status">
          Loading priority policy…
        </p>
      </PolicyCardFrame>
    )
  }

  const errors: PolicyFormErrors = policyFormErrors(form)
  const saved = policyFormFromFields(policy)
  const defaults = policyFormFromFields(policy.defaults)
  const dirty = !policyFormsEqual(form, saved)
  const invalid = Object.keys(errors).length > 0

  function updateField(field: ThresholdField, value: string) {
    setForm((current) => (current ? { ...current, [field]: value } : current))
    setMessage("")
  }

  function updateSla(field: SlaField, value: string) {
    setForm((current) =>
      current
        ? { ...current, sla: { ...current.sla, [field]: value } }
        : current,
    )
    setMessage("")
  }

  async function save() {
    if (!form) return
    const update = policyUpdateFromForm(form, reason)
    if (!update) return
    setSaving(true)
    setError("")
    setMessage("")
    try {
      const result = await ProjectsService.updateProjectPolicy({
        project_id: projectId,
        projectPolicyUpdate: update,
      })
      setReason("")
      setMessage(policySaveMessage(result))
      queryClient.setQueryData(
        workbenchQueryKeys.projectPolicy(projectId),
        result.policy,
      )
      await invalidateProjectScopedWorkbenchQueries(queryClient, projectId)
    } catch (caught) {
      setError(apiErrorMessage("Policy update failed", caught))
    } finally {
      setSaving(false)
    }
  }

  return (
    <PolicyCardFrame
      badge={
        <VpwBadge tone={policy.is_default ? "neutral" : "info"}>
          {policy.is_default ? "Defaults" : `Version ${policy.version}`}
        </VpwBadge>
      }
    >
      <form
        className="grid gap-5"
        onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}
      >
        <fieldset className="grid gap-3">
          <legend className="mb-2 text-sm font-semibold">
            Base priority thresholds
          </legend>
          {priorityRows.map((row) => (
            <div
              className="grid gap-2 sm:grid-cols-[6rem_minmax(0,1fr)_minmax(0,1fr)] sm:items-end"
              key={row.label}
            >
              <div className="text-sm">
                <strong>{row.label}</strong>
                <span className="block text-xs text-[var(--vpw-text-muted)]">
                  {row.rule}
                </span>
              </div>
              <PolicyNumberField
                error={errors[row.epss]}
                id={`${idPrefix}-${row.epss}`}
                label={`${row.label} EPSS threshold`}
                max="1"
                onChange={(value) => updateField(row.epss, value)}
                step="0.01"
                value={form[row.epss]}
              />
              <PolicyNumberField
                error={errors[row.cvss]}
                id={`${idPrefix}-${row.cvss}`}
                label={`${row.label} CVSS threshold`}
                max="10"
                onChange={(value) => updateField(row.cvss, value)}
                step="0.1"
                value={form[row.cvss]}
              />
            </div>
          ))}
        </fieldset>
        <fieldset className="grid gap-3">
          <legend className="mb-2 text-sm font-semibold">
            SLA response targets (hours)
          </legend>
          <div className="grid gap-3 sm:grid-cols-4">
            {slaFields.map((field) => (
              <PolicyNumberField
                error={errors[`sla.${field}`]}
                hint={slaHoursHint(form.sla[field])}
                id={`${idPrefix}-sla-${field}`}
                key={field}
                label={`${slaLabels[field]} SLA hours`}
                max="8760"
                onChange={(value) => updateSla(field, value)}
                step="1"
                value={form.sla[field]}
              />
            ))}
          </div>
        </fieldset>
        <div className="grid gap-2">
          <Label htmlFor={`${idPrefix}-reason`}>Reason (optional)</Label>
          <Input
            id={`${idPrefix}-reason`}
            maxLength={500}
            onChange={(event) => setReason(event.target.value)}
            placeholder="For example: risk committee decision of 2026-09-28"
            value={reason}
          />
        </div>
        {errors.form ? (
          <p className="text-sm text-[var(--vpw-red)]" role="alert">
            {errors.form}
          </p>
        ) : null}
        {error ? (
          <p className="text-sm text-[var(--vpw-red)]" role="alert">
            {error}
          </p>
        ) : null}
        {message ? (
          <p className="text-sm" role="status">
            {message}
          </p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button disabled={saving || !dirty || invalid} type="submit">
            {saving ? "Saving…" : "Save and re-evaluate"}
          </Button>
          <Button
            disabled={saving || policyFormsEqual(form, defaults)}
            onClick={() => {
              setForm(defaults)
              setMessage("")
            }}
            type="button"
            variant="outline"
          >
            Use defaults
          </Button>
        </div>
      </form>
    </PolicyCardFrame>
  )
}

function PolicyCardFrame({
  badge,
  children,
}: {
  badge?: ReactNode
  children: ReactNode
}) {
  return (
    <section
      aria-label="Priority policy"
      className="project-drawer-card flex flex-col gap-4 rounded-xl border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-5"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h3 className="font-bold text-sm text-[var(--vpw-text-primary)]">
            Priority policy
          </h3>
          <p className="text-xs text-[var(--vpw-text-secondary)]">
            Thresholds for the base priority rule and the SLA each priority
            gets. Saving records a new version and re-evaluates this project's
            findings; decisions keep the policy they were made with.
          </p>
        </div>
        {badge ? <div className="shrink-0">{badge}</div> : null}
      </div>
      {children}
    </section>
  )
}

function PolicyNumberField({
  error,
  hint,
  id,
  label,
  max,
  onChange,
  step,
  value,
}: {
  error?: string
  hint?: string
  id: string
  label: string
  max: string
  onChange: (value: string) => void
  step: string
  value: string
}) {
  return (
    <div className="grid gap-1">
      <Label className="text-xs" htmlFor={id}>
        {label}
      </Label>
      <Input
        aria-invalid={Boolean(error)}
        id={id}
        inputMode="decimal"
        max={max}
        min="0"
        onChange={(event) => onChange(event.target.value)}
        step={step}
        type="number"
        value={value}
      />
      {error ? (
        <span className="text-xs text-[var(--vpw-red)]">{error}</span>
      ) : hint ? (
        <span className="text-xs text-[var(--vpw-text-muted)]">{hint}</span>
      ) : null}
    </div>
  )
}
