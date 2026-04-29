# VPW-039 Projects Workflow Evidence

VPW-039 adds the authenticated Projects page workflow through the generated
OpenAPI client.

## Scope Verified

- The Projects route lists visible projects from `ProjectsService.readProjects()`.
- Users can create projects through a validated form.
- The selected project appears in the list and in a detail header with created
  and updated timestamps.
- Users can edit project name and description through
  `ProjectsService.updateProject()`.
- Users can delete a project only after checking a visible confirmation box.
- The Playwright smoke verifies create, list, detail, edit, and delete through
  the browser UI.
- All project API calls go through the generated client and therefore inherit
  the configured bearer token.

## Screenshot Evidence

The Projects page screenshot is saved at:

```text
docs/evidence/vpw-039-projects.png
```

Screenshot file:

```text
docs/evidence/vpw-039-projects.png: PNG image data, 1440 x 1100, 8-bit/color RGB, non-interlaced
```

## E2E Create Project Proof

The Playwright smoke:

- logs in through the template login form,
- opens `/projects`,
- verifies required project-name validation,
- creates `VPW UI Project`,
- verifies it in the Projects list and detail header,
- edits it to `VPW UI Project Edited`,
- confirms deletion with the checkbox,
- deletes the project and verifies it is removed.

```text
> frontend@0.0.0 test
> playwright test

Running 1 test using 1 worker
  ✓  1 [chromium] › tests/template-login-status.spec.ts:3:1 › template login reaches authenticated Workbench status shell (2.1s)

  1 passed (7.2s)
```

## Verification

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix frontend run test
make frontend-check
python3 -m mkdocs build --clean
git diff --check
```

Observed results:

```text
frontend lint: passed, 25 files checked
frontend build: passed
Playwright login/projects smoke: 1 passed
make frontend-check: passed
mkdocs build: passed
git diff --check: passed
```

## Residual Risk

The Projects workflow is currently rendered inside the shared Workbench shell.
Later frontend decomposition can split route-specific page components once more
routes have dedicated data workflows.
