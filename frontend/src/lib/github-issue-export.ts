import type {
  GitHubIssueExportCreate,
  GitHubIssueExportSettingsPublic,
} from "../api-client"

const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/

export type GitHubIssueExportReadiness =
  | { ready: true; tokenEnv: string }
  | { ready: false; reason: string; tokenEnv: string | null }

export function isValidGitHubRepository(repository: string) {
  return REPOSITORY_PATTERN.test(repository.trim())
}

export function githubIssueExportReadiness(
  settings: GitHubIssueExportSettingsPublic | null | undefined,
): GitHubIssueExportReadiness {
  const tokenEnv = settings?.token_env?.trim() || null
  if (!tokenEnv) {
    return {
      ready: false,
      reason: "GitHub issue creation is unavailable until export settings load.",
      tokenEnv: null,
    }
  }
  if (!settings?.token_configured) {
    return {
      ready: false,
      reason: `Set ${tokenEnv} in the environment of the Workbench process to create issues.`,
      tokenEnv,
    }
  }
  return { ready: true, tokenEnv }
}

export function buildGitHubIssueExportRequest({
  findingIds,
  repository,
  tokenEnv,
}: {
  findingIds: readonly string[]
  repository: string
  tokenEnv: string
}): GitHubIssueExportCreate {
  return {
    finding_ids: [...findingIds],
    repository: repository.trim(),
    dry_run: false,
    token_env: tokenEnv,
  }
}
