import type {
  ProjectPolicyFields,
  ProjectPolicyUpdate,
  ProjectPolicyUpdatePublic,
} from "../api-client"

export const thresholdFields = [
  "critical_epss_threshold",
  "critical_cvss_threshold",
  "high_epss_threshold",
  "high_cvss_threshold",
  "medium_epss_threshold",
  "medium_cvss_threshold",
] as const
export const slaFields = ["critical", "high", "medium", "low"] as const

export type ThresholdField = (typeof thresholdFields)[number]
export type SlaField = (typeof slaFields)[number]
export type PolicyFormState = Record<ThresholdField, string> & {
  sla: Record<SlaField, string>
}
export type PolicyFormErrors = Partial<
  Record<ThresholdField | `sla.${SlaField}` | "form", string>
>

export const MAX_SLA_HOURS = 8760

export function policyFormFromFields(
  fields: ProjectPolicyFields,
): PolicyFormState {
  return {
    critical_cvss_threshold: String(fields.critical_cvss_threshold),
    critical_epss_threshold: String(fields.critical_epss_threshold),
    high_cvss_threshold: String(fields.high_cvss_threshold),
    high_epss_threshold: String(fields.high_epss_threshold),
    medium_cvss_threshold: String(fields.medium_cvss_threshold),
    medium_epss_threshold: String(fields.medium_epss_threshold),
    sla: {
      critical: String(fields.sla_hours.critical),
      high: String(fields.sla_hours.high),
      low: String(fields.sla_hours.low),
      medium: String(fields.sla_hours.medium),
    },
  }
}

function numberValue(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return Number.NaN
  return Number(trimmed)
}

export function policyFormErrors(form: PolicyFormState): PolicyFormErrors {
  const errors: PolicyFormErrors = {}
  for (const field of thresholdFields) {
    const value = numberValue(form[field])
    const max = field.endsWith("epss_threshold") ? 1 : 10
    if (!Number.isFinite(value) || value < 0 || value > max) {
      errors[field] = `Enter a number from 0 to ${max}.`
    }
  }
  for (const field of slaFields) {
    const value = numberValue(form.sla[field])
    if (!Number.isInteger(value) || value < 1 || value > MAX_SLA_HOURS) {
      errors[`sla.${field}`] = `Enter whole hours from 1 to ${MAX_SLA_HOURS}.`
    }
  }
  if (Object.keys(errors).length) return errors
  const epss = [
    numberValue(form.critical_epss_threshold),
    numberValue(form.high_epss_threshold),
    numberValue(form.medium_epss_threshold),
  ]
  if (!(epss[0] >= epss[1] && epss[1] >= epss[2])) {
    errors.form =
      "EPSS thresholds must descend from Critical to High to Medium."
  } else if (
    numberValue(form.high_cvss_threshold) <
    numberValue(form.medium_cvss_threshold)
  ) {
    errors.form =
      "The High CVSS threshold cannot be below the Medium threshold."
  } else {
    const hours = slaFields.map((field) => numberValue(form.sla[field]))
    if (hours.some((value, index) => index > 0 && value < hours[index - 1])) {
      errors.form =
        "More urgent priorities cannot get a longer SLA than less urgent ones."
    }
  }
  return errors
}

export function policyUpdateFromForm(
  form: PolicyFormState,
  reason: string,
): ProjectPolicyUpdate | null {
  if (Object.keys(policyFormErrors(form)).length) return null
  const trimmedReason = reason.trim()
  return {
    critical_cvss_threshold: numberValue(form.critical_cvss_threshold),
    critical_epss_threshold: numberValue(form.critical_epss_threshold),
    high_cvss_threshold: numberValue(form.high_cvss_threshold),
    high_epss_threshold: numberValue(form.high_epss_threshold),
    medium_cvss_threshold: numberValue(form.medium_cvss_threshold),
    medium_epss_threshold: numberValue(form.medium_epss_threshold),
    reevaluate: true,
    ...(trimmedReason ? { reason: trimmedReason } : {}),
    sla_hours: {
      critical: numberValue(form.sla.critical),
      high: numberValue(form.sla.high),
      low: numberValue(form.sla.low),
      medium: numberValue(form.sla.medium),
    },
  }
}

export function policyFormsEqual(a: PolicyFormState, b: PolicyFormState) {
  return (
    thresholdFields.every(
      (field) => numberValue(a[field]) === numberValue(b[field]),
    ) &&
    slaFields.every(
      (field) => numberValue(a.sla[field]) === numberValue(b.sla[field]),
    )
  )
}

export function slaHoursHint(value: string) {
  const hours = numberValue(value)
  if (!Number.isInteger(hours) || hours < 1) return ""
  if (hours % 24 !== 0) return `${hours} hours`
  const days = hours / 24
  return days === 1 ? "1 day" : `${days} days`
}

export function policySaveMessage(result: ProjectPolicyUpdatePublic) {
  if (!result.changed) return "The policy did not change."
  const version = `Saved policy version ${result.policy.version}.`
  if (result.evaluation_run_id) {
    return `${version} Findings are being re-evaluated with the new policy.`
  }
  return result.evaluation_skipped_reason
    ? `${version} ${result.evaluation_skipped_reason}`
    : version
}
