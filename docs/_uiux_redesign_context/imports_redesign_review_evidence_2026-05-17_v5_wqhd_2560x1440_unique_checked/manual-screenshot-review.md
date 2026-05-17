# Manual Screenshot Review

Review date: 2026-05-17

Verdict: use this v5 packet. Earlier v1/v2/v3/v4 packets are superseded.

## Duplicate Cleanup

- Removed exact duplicates: `02_import-center_wqhd-fullpage_2560x1440.png`, `05_new-import_step-1_wqhd-fullpage_2560x1440.png`, `21_supported-formats_table_wqhd-fullpage_2560x1440.png`.
- Removed perceptual duplicates: `09_new-import_step-3_wqhd-fullpage_2560x1440.png`, `11_new-import_step-4_wqhd-fullpage_2560x1440.png`.
- Removed confusing redundant review aid: `19_supported-formats_cyclonedx-fullcontent_2560x2200.png`.
- Kept similar but meaningfully different state pair: `04_new-import_step-2_missing-file_wqhd_2560x1440.png` and `05_new-import_step-2_file-check-passed_wqhd_2560x1440.png`.

## Per-Screenshot Review

- `01_import-center_wqhd_2560x1440.png`: Import Center content is loaded; no skeleton; above-the-fold table and summary blocks visible.
- `02_import-center_diagnostics-drawer_wqhd_2560x1440.png`: WQHD diagnostics drawer was recaptured after waiting for the slide-in animation; measured `left=1888`, `right=2560`, `width=672`, `viewportWidth=2560`; no clipping and no route error overlay.
- `03_new-import_step-1_choose-source_wqhd_2560x1440.png`: Wizard step 1 is visible with source choices and summary rail.
- `04_new-import_step-2_missing-file_wqhd_2560x1440.png`: Missing-file disabled state is visible.
- `05_new-import_step-2_file-check-passed_wqhd_2560x1440.png`: File-selected and file-check-passed state is visible.
- `06_new-import_step-3_add-context_wqhd_2560x1440.png`: Optional context step is visible, including context choices and summary rail.
- `07_new-import_step-4_review-viewport_wqhd_2560x1440.png`: Real WQHD viewport for review step is visible; it naturally does not show the entire scrollable page.
- `08_new-import_step-4_review-fullcontent_2560x3200.png`: Complete review step is visible, including readiness and import summary.
- `09_new-import_mobile-summary_390x844.png`: Mobile wizard summary is visible and not horizontally clipped.
- `10_run-detail_overview_wqhd_2560x1440.png`: Run detail overview tab is visible.
- `11_run-detail_findings_wqhd_2560x1440.png`: Findings tab truthful triage-link state is visible.
- `12_run-detail_diagnostics_wqhd_2560x1440.png`: Diagnostics tab is visible.
- `13_run-detail_evidence_wqhd_2560x1440.png`: Evidence tab empty state is visible; no route failure overlay.
- `14_run-detail_metadata_wqhd_2560x1440.png`: Metadata tab is visible.
- `15_run-detail_diagnostics-drawer_mobile_390x844.png`: Mobile drawer is fully settled inside the viewport.
- `16_supported-formats_table_wqhd_2560x1440.png`: Supported formats table and detail panel are visible.
- `17_supported-formats_cyclonedx-detail_wqhd_2560x1440.png`: CycloneDX detail panel is visible.
- `18_supported-formats_search-nessus_wqhd_2560x1440.png`: Search-filtered Nessus state is visible.

## Technical Checks

- Exact duplicate SHA-256 count in `screenshots/`: 0.
- Perceptual near-duplicate candidates left: only Step 2 missing-file vs Step 2 file-check-passed, which are intentionally different states.
- `evidence-metrics.json` reports no console errors/warnings, no framework overlay, no LazyRoute skeleton, no route-failure overlay, and no horizontal overflow.
- Desktop diagnostics drawer metrics after recapture: `left=1888`, `right=2560`, `width=672`, `viewportWidth=2560`.
