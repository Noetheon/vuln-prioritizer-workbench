import assert from "node:assert/strict"
import test from "node:test"
import type { ProjectPolicyPublic } from "../src/api-client"
import {
  policyFormErrors,
  policyFormFromFields,
  policyFormsEqual,
  policySaveMessage,
  policyUpdateFromForm,
  slaHoursHint,
} from "../src/lib/project-policy-form.ts"

const defaults = {
  critical_cvss_threshold: 7,
  critical_epss_threshold: 0.7,
  high_cvss_threshold: 9,
  high_epss_threshold: 0.4,
  medium_cvss_threshold: 7,
  medium_epss_threshold: 0.1,
  sla_hours: { critical: 24, high: 168, low: 2160, medium: 720 },
}

const policy: ProjectPolicyPublic = {
  ...defaults,
  defaults,
  is_default: true,
  project_id: "project-1",
  version: 0,
}

test("policy forms round-trip into update requests with trimmed reasons", () => {
  const form = policyFormFromFields(defaults)
  assert.equal(form.high_cvss_threshold, "9")
  assert.equal(form.sla.medium, "720")
  assert.deepEqual(policyFormErrors(form), {})
  assert.deepEqual(policyUpdateFromForm(form, "  Committee  "), {
    ...defaults,
    reason: "Committee",
    reevaluate: true,
  })
  assert.equal("reason" in (policyUpdateFromForm(form, " ") ?? {}), false)
  assert.equal(
    policyFormsEqual(form, { ...form, high_cvss_threshold: "9.0" }),
    true,
  )
  assert.equal(
    policyFormsEqual(form, { ...form, high_cvss_threshold: "8" }),
    false,
  )
  assert.equal(
    policyFormsEqual(form, { ...form, sla: { ...form.sla, low: "100" } }),
    false,
  )
})

test("policy forms reject out-of-range and inconsistent values", () => {
  const form = policyFormFromFields(defaults)
  assert.deepEqual(
    Object.keys(
      policyFormErrors({
        ...form,
        critical_epss_threshold: "1.5",
        high_cvss_threshold: "",
        sla: { ...form.sla, critical: "0.5", low: "9000" },
      }),
    ).sort(),
    [
      "critical_epss_threshold",
      "high_cvss_threshold",
      "sla.critical",
      "sla.low",
    ],
  )
  assert.match(
    policyFormErrors({ ...form, high_epss_threshold: "0.9" }).form ?? "",
    /EPSS thresholds must descend/,
  )
  assert.match(
    policyFormErrors({ ...form, high_cvss_threshold: "6" }).form ?? "",
    /High CVSS threshold/,
  )
  assert.match(
    policyFormErrors({ ...form, sla: { ...form.sla, high: "12" } }).form ?? "",
    /longer SLA/,
  )
  assert.equal(
    policyUpdateFromForm({ ...form, medium_cvss_threshold: "x" }, ""),
    null,
  )
})

test("SLA hints read hours as days when they divide evenly", () => {
  assert.equal(slaHoursHint("24"), "1 day")
  assert.equal(slaHoursHint("168"), "7 days")
  assert.equal(slaHoursHint("36"), "36 hours")
  assert.equal(slaHoursHint("0"), "")
  assert.equal(slaHoursHint("abc"), "")
})

test("save messages say what happened to the re-evaluation", () => {
  assert.equal(
    policySaveMessage({ changed: false, policy }),
    "The policy did not change.",
  )
  const saved = { ...policy, is_default: false, version: 3 }
  assert.equal(
    policySaveMessage({
      changed: true,
      evaluation_run_id: "run-1",
      policy: saved,
    }),
    "Saved policy version 3. Findings are being re-evaluated with the new policy.",
  )
  assert.equal(
    policySaveMessage({
      changed: true,
      evaluation_skipped_reason:
        "No existing findings are available for reevaluation.",
      policy: saved,
    }),
    "Saved policy version 3. No existing findings are available for reevaluation.",
  )
  assert.equal(
    policySaveMessage({ changed: true, policy: saved }),
    "Saved policy version 3.",
  )
})
