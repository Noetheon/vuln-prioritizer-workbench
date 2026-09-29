import { useMutation, useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { GithubIssuesService } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { apiErrorMessage } from "@/lib/app-errors"
import {
  buildGitHubIssueExportRequest,
  githubIssueExportReadiness,
  isValidGitHubRepository,
} from "@/lib/github-issue-export"
import { workbenchQueryKeys } from "@/workbench/workbench-query-keys"

export function FindingGitHubIssue({
  findingId,
  projectId,
}: {
  findingId: string
  projectId: string
}) {
  const [open, setOpen] = useState(false)
  const [repository, setRepository] = useState("")
  const preview = useMutation({
    mutationFn: () =>
      GithubIssuesService.previewProjectGithubIssues({
        project_id: projectId,
        gitHubIssuePreviewCreate: { finding_ids: [findingId] },
      }),
  })
  const exportSettings = useQuery({
    enabled: open,
    queryFn: ({ signal }) =>
      GithubIssuesService.readGithubIssueExportSettings({ signal }),
    queryKey: workbenchQueryKeys.githubIssueExportSettings(),
  })
  const readiness = githubIssueExportReadiness(exportSettings.data)
  const publish = useMutation({
    mutationFn: (tokenEnv: string) =>
      GithubIssuesService.exportProjectGithubIssues({
        project_id: projectId,
        gitHubIssueExportCreate: buildGitHubIssueExportRequest({
          findingIds: [findingId],
          repository,
          tokenEnv,
        }),
      }),
  })
  const issue = preview.data?.data?.[0]
  const result = publish.data?.data?.[0]
  const validRepository = isValidGitHubRepository(repository)

  function openPreview() {
    publish.reset()
    preview.mutate()
    setOpen(true)
  }

  return (
    <>
      <Button variant="outline" size="sm" onClick={openPreview}>
        Preview GitHub issue
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>GitHub issue preview</DialogTitle>
            <DialogDescription>
              Review the finding scope and prepared Markdown before creating an
              issue in the repository you specify.
            </DialogDescription>
          </DialogHeader>
          {preview.isPending ? <p role="status">Preparing preview…</p> : null}
          {preview.isError ? (
            <p role="alert">
              {apiErrorMessage("Issue preview unavailable", preview.error)}
            </p>
          ) : null}
          {preview.isSuccess && !issue ? (
            <p>No exportable issue is available for this finding.</p>
          ) : null}
          {issue ? (
            <>
              <h3 className="font-semibold">{issue.title}</h3>
              <section aria-label="Prepared issue Markdown">
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border p-3 text-xs">
                  {issue.body}
                </pre>
              </section>
              <p className="text-xs text-[var(--vpw-text-secondary)]">
                Labels: {issue.labels?.join(", ") || "None"}
              </p>
              <div className="grid gap-2">
                <Label htmlFor="issue-repository">
                  Repository (owner/name)
                </Label>
                <Input
                  id="issue-repository"
                  value={repository}
                  onChange={(event) => {
                    setRepository(event.target.value)
                    publish.reset()
                  }}
                  placeholder="organization/repository"
                  disabled={publish.isPending}
                />
                <p className="text-xs text-[var(--vpw-text-muted)]">
                  {readiness.ready
                    ? `Uses the GitHub token from the ${readiness.tokenEnv} environment variable of this Workbench.`
                    : readiness.reason}
                </p>
              </div>
              {publish.isError ? (
                <p role="alert">
                  {apiErrorMessage(
                    "GitHub issue creation failed",
                    publish.error,
                  )}
                </p>
              ) : null}
              {result ? (
                <p role="status">
                  {result.status === "created"
                    ? "Issue created."
                    : "An issue already exists for this finding."}
                  {result.issue_url ? (
                    <>
                      {" "}
                      <a
                        href={result.issue_url}
                        target="_blank"
                        rel="noreferrer"
                        className="underline"
                      >
                        Open GitHub issue
                      </a>
                    </>
                  ) : null}
                </p>
              ) : null}
              <DialogFooter>
                <Button
                  disabled={
                    !readiness.ready ||
                    !validRepository ||
                    publish.isPending ||
                    Boolean(result)
                  }
                  onClick={() => {
                    if (readiness.ready) publish.mutate(readiness.tokenEnv)
                  }}
                >
                  {publish.isPending
                    ? "Creating issue…"
                    : `Create GitHub issue${validRepository ? ` in ${repository.trim()}` : ""}`}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  )
}
