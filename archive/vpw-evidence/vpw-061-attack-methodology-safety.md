# VPW-061 ATT&CK Methodology And Safety Evidence

VPW-061 documents the ATT&CK-Lite methodology and adds automated safety checks
for demo mappings and snapshot reports.

## Delivered Scope

- Added explicit Tactic/Technique/Procedure boundaries to
  `docs/attack-ttp-methodology.md`.
- Added confidence, limitations, and a mapping review checklist for curated
  local ATT&CK mappings.
- Linked the checklist from `docs/methodology.md`,
  `docs/workbench-attack-methodology.md`, and the ATT&CK mapping review issue
  template.
- Updated CLI Markdown, Workbench summary, and HTML executive report wording so
  ATT&CK is framed as source-backed defensive context, not proof of local
  exploitation or procedure guidance.
- Added automated safety tests for demo mappings, snapshot reports, non-KEV
  ATT&CK report wording, and Workbench summary safety wording.

## Docs And Checklist

- Methodology and checklist:
  `docs/attack-ttp-methodology.md`
- Workbench report safety contract:
  `docs/workbench-attack-methodology.md`
- General methodology cross-link:
  `docs/methodology.md`
- Review issue template:
  `.github/ISSUE_TEMPLATE/attack_mapping_review.md`

## Safety Test Excerpt

```text
python3 -m pytest -q backend/tests/test_attack_report_safety.py \
  backend/tests/test_reporter.py::test_generate_html_report_renders_attack_and_waiver_states \
  --no-cov

....                                                                     [100%]
4 passed in 0.02s
```

The safety test scans:

- `data/cve_attack_mappings.yml`
- `data/attack/local_curated_low_confidence_vpw058.yml`
- `docs/example_attack_report.md`
- `docs/example_attack_compare.md`
- `docs/example_attack_explain.json`
- `docs/examples/example_report.html`
- `docs/evidence/vpw-060-attack-navigator-layer.json`

## Report Excerpts

Markdown ATT&CK methodology excerpt from `docs/example_attack_report.md`:

```text
- ATT&CK context is sourced from explicit local files only.
- No heuristic or LLM-generated CVE-to-ATT&CK mapping is performed.
- ATT&CK relevance is reported separately and does not change the primary priority score.
- ATT&CK context is defensive context; it is not proof that exploitation occurred.
- Tactics describe objectives, techniques describe behavior categories, and procedure-level details remain out of scope.
```

Markdown ATT&CK summary excerpt from `docs/example_attack_report.md`:

```text
- ATT&CK mappings are imported from explicit local CTID or local CSV files only.
- Reported tactics and techniques are defensive review context, not operational procedure guidance.
```

HTML executive report excerpt from `docs/examples/example_report.html`:

```html
<h3>Illustrative Defensive TTP Sequence</h3>
<p class="er-muted">
  Defensive review sequence only. Not a confirmed attack path and not procedure guidance.
</p>
```

## Snapshot Reports Checked

- `make demo-attack-report`: regenerated `docs/example_attack_report.md`.
- `make demo-attack-compare`: regenerated `docs/example_attack_compare.md`.
- `make demo-html-report`: regenerated `docs/examples/example_report.html`.

## Residual Risk

Source-owned NVD, KEV, and CTID text can contain words such as "exploited" or
upstream vulnerability descriptions. VPW-061 safety tests focus on blocking
VPW-authored payloads, commands, reproduction steps, procedure guidance, and
unsupported local exploitation claims while preserving cited defensive source
context.
