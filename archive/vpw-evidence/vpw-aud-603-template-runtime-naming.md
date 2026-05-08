# VPW-AUD-603 Legacy Template Runtime Naming Audit

Issue: VPW-AUD-603
Category: Repo Hygiene
Date: 2026-05-08

## Active Runtime Decision

Active backend service names now use Workbench terminology:

- `WorkbenchAnalysisError`
- `WorkbenchAnalysisResult`
- `DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT`
- Workbench-branded package, route, repository, service, report, and security
  module docstrings

## Retained Compatibility Aliases

The following template-era names remain intentionally because they can be used
by older local tests, scripts, or self-hosted data paths:

- `TemplateAnalysisError`, `TemplateAnalysisResult`, and
  `DEFAULT_TEMPLATE_PROVIDER_SNAPSHOT` as aliases to the Workbench-branded names.
- `resolve_template_provider_snapshot_path` and
  `resolve_template_attack_artifact_path` as import-path aliases.
- `TemplateProviderUpdateConflict` and
  `TemplateProviderUpdateValidationError` as provider-update aliases.
- `app.state.template_settings` and `app.state.template_engine` as state aliases
  for older local test and script integrations.
- `template.db` and `data/template-*` storage roots as migration fallbacks only
  when existing data is present and the Workbench-branded path is empty.
- `template-*` Compose volume names as documented historical compatibility
  names for attach, backup, restore, or rename migration only.

## Remaining Non-Runtime Uses

Remaining `template` matches are accepted where they are not active runtime
names: historical migration docs, GitHub issue or summary templates, decision
template fields in report contracts, CSS `grid-template-*`, test filenames and
fixtures, and checked-in example artifact filenames.

## Safety Decision

No existing self-hosted data path was removed. Runtime defaults stay
Workbench-branded, while migration aliases are explicitly documented and tested.
