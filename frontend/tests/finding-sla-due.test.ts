import assert from "node:assert/strict"
import test from "node:test"
import {
  slaDueDetail,
  slaDueSummary,
  slaFilterOptions,
  slaStateLabel,
} from "../src/lib/finding-sla-due.ts"

const dueAt = "2026-09-30T14:00:00Z"
const dateLabel = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
}).format(new Date(dueAt))
const dateTimeLabel = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
}).format(new Date(dueAt))

test("SLA filter options and labels cover every server state", () => {
  assert.deepEqual(
    slaFilterOptions.map((option) => option.value),
    ["overdue", "due_soon", "on_track"],
  )
  assert.equal(slaStateLabel("due_soon"), "Due soon")
  assert.equal(slaStateLabel(""), "")
  assert.equal(slaStateLabel(null), "")
})

test("due summaries use absolute dates and the server-decided state", () => {
  assert.deepEqual(slaDueSummary({ sla_due_at: dueAt, sla_state: "overdue" }), {
    label: `Overdue since ${dateLabel}`,
    title: `SLA due ${dateTimeLabel}`,
    tone: "critical",
  })
  assert.deepEqual(
    slaDueSummary({ sla_due_at: dueAt, sla_state: "due_soon" }),
    {
      label: `Due ${dateTimeLabel}`,
      title: `SLA due ${dateTimeLabel}`,
      tone: "warning",
    },
  )
  assert.deepEqual(
    slaDueSummary({ sla_due_at: dueAt, sla_state: "on_track" }),
    {
      label: `Due ${dateLabel}`,
      title: `SLA due ${dateTimeLabel}`,
      tone: "neutral",
    },
  )
})

test("closed, governed, or malformed findings have no due summary", () => {
  assert.equal(slaDueSummary({ sla_due_at: null, sla_state: null }), null)
  assert.equal(slaDueSummary({ sla_due_at: dueAt, sla_state: null }), null)
  assert.equal(
    slaDueSummary({ sla_due_at: "not-a-date", sla_state: "overdue" }),
    null,
  )
  assert.equal(
    slaDueDetail({ sla_due_at: null, sla_state: null, status: "resolved" }),
    "Not tracked for closed or governed findings",
  )
  assert.equal(
    slaDueDetail({ sla_due_at: null, sla_state: null, status: "in_review" }),
    "No SLA target recorded",
  )
  assert.equal(
    slaDueDetail({ sla_due_at: dueAt, sla_state: "overdue", status: "open" }),
    `${dateTimeLabel} · Overdue`,
  )
})
