import assert from "node:assert/strict"
import { readFileSync, readdirSync } from "node:fs"
import { relative } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const repoRoot = new URL("..", import.meta.url)
const srcRoot = new URL("../src/", import.meta.url)
const testsRoot = new URL("../tests/", import.meta.url)

type SourceFile = {
  path: string
  relativePath: string
}

function sourceFiles(dir: URL): SourceFile[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = new URL(entry.name, `${dir.href}/`)
    const absolutePath = fileURLToPath(path)
    const relativePath = relative(fileURLToPath(repoRoot), absolutePath)

    if (entry.isDirectory()) {
      if (relativePath === "src/client") return []
      return sourceFiles(path)
    }

    if (!/\.(?:ts|tsx)$/.test(entry.name)) return []
    if (entry.name.endsWith(".gen.ts")) return []

    return [{ path: absolutePath, relativePath }]
  })
}

const activeSourceFiles = sourceFiles(srcRoot)
const playwrightSpecFiles = sourceFiles(testsRoot).filter(({ relativePath }) =>
  relativePath.endsWith(".spec.ts"),
)

const forbiddenProductDirectionCopy = [
  /\blogin\b/i,
  /\bsign out\b/i,
  /\brbac\b/i,
  /\bsso\b/i,
  /\bapi tokens?\b/i,
  /\bscanner\b/i,
  /\bprobing\b/i,
  /\bexploits?\b/i,
  /\bexploited\b/i,
  /\bexploitation\b/i,
  /\bpoc\b/i,
  /\bautopatch(?:ing)?\b/i,
]

const allowedCurrentCopy = [
  {
    path: /^src\/lib\/demo-data(?:-[a-z-]+)?\.ts$/,
    context: /\b(?:exploited in the wild|known[- ]exploited|active exploitation|actively exploited|exploitation (?:observed|probability|signal|risk)|chained exploitation|defensive prioritization|detection planning|remediation context|exploit public-facing application)\b/i,
  },
  {
    path: /^src\/components\/(?:dashboard|finding-detail|findings|providers|reports|vpw)\//,
    context: /\b(?:known[- ]exploited|known exploited vulnerabilities|exploitation (?:probability|risk)|exploit probability|exploit-probability|exploit likelihood|exploited signals?|defensive|detection coverage review|no exploit steps|no proof of exploitation|does not prove compromise|confirmed prioritization signal)\b/i,
  },
  {
    path: /^src\/components\/settings\//,
    context: /\b(?:exploit probability source|known exploited vulnerabilities signal)\b/i,
  },
  {
    path: /^src\/components\/(?:assets|dashboard|finding-detail|findings|projects)\//,
    context: /\bscanner\b/i,
  },
  {
    path: /^src\/(?:components\/imports|lib\/import-format-(?:metadata|catalog|types)\.ts)/,
    context:
      /\b(?:scanner exports|network scanner exports|parsed locally|does not scan networks|category: "scanner"|scanner)\b/i,
  },
  {
    path: /^tests\/(?:accessibility|finding-ttp-context|findings-route-integration|responsive-shell|settings-local-access|ui-evidence-screenshots|ui-smoke|workbench-entry-status)\.spec\.ts$/,
    context: /known exploited|does not prove exploitation|legacy sign out|api token management|tohavecount\(0\)|not\.tocontaintext|No exploit steps/i,
  },
]

function isAllowedCurrentCopy(relativePath: string, nearby: string) {
  const normalizedNearby = nearby.replace(/\s+/g, " ")
  return allowedCurrentCopy.some(
    (allowance) =>
      allowance.path.test(relativePath) &&
      allowance.context.test(normalizedNearby),
  )
}

test("active product copy does not point toward auth, scanner, exploit, or autopatching features", () => {
  const offenders = [...activeSourceFiles, ...playwrightSpecFiles].flatMap(
    ({ path, relativePath }) => {
      const lines = readFileSync(path, "utf8").split(/\r?\n/)

      return lines.flatMap((line, index) => {
        const nearby = lines
          .slice(Math.max(0, index - 1), Math.min(lines.length, index + 2))
          .join("\n")

        if (isAllowedCurrentCopy(relativePath, nearby)) return []

        return forbiddenProductDirectionCopy
          .filter((term) => term.test(line))
          .map((term) => `${relativePath}:${index + 1}: ${term}: ${line.trim()}`)
      })
    },
  )

  assert.deepEqual(offenders, [])
})

const attackFramingWords =
  /\b(?:defensive|reviewed?|framing|context|mapping|mapped|coverage|scope|navigator|source|import|options|tabstrigger)\b/i
const attackExploitStepWords =
  /\b(?:exploit steps?|payloads?|poc guidance|active probing|offensive)\b/i

test("ATT&CK source copy stays framed as defensive review context", () => {
  const offenders = activeSourceFiles.flatMap(({ path, relativePath }) => {
    const lines = readFileSync(path, "utf8").split(/\r?\n/)

    return lines.flatMap((line, index) => {
      if (!line.includes("ATT&CK")) return []

      const nearby = lines
        .slice(Math.max(0, index - 3), Math.min(lines.length, index + 4))
        .join("\n")

      const findings = []
      if (!attackFramingWords.test(nearby)) {
        findings.push(`${relativePath}:${index + 1}: missing defensive/review framing`)
      }
      if (attackExploitStepWords.test(nearby)) {
        findings.push(`${relativePath}:${index + 1}: includes exploit-step wording`)
      }

      return findings
    })
  })

  assert.deepEqual(offenders, [])
})
