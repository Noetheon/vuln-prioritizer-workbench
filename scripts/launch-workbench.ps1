param(
  [ValidateSet("start", "stop", "status", "logs", "smoke", "reset", "update", "diagnostics", "help")]
  [string]$Command = "start"
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

$ComposeFiles = @("-f", "compose.yml", "-f", "compose.override.yml")

function Get-ProcessEnv {
  param([Parameter(Mandatory = $true)][string]$Name)
  return [Environment]::GetEnvironmentVariable($Name, "Process")
}

function Set-DefaultEnv {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Value
  )
  if ([string]::IsNullOrWhiteSpace((Get-ProcessEnv $Name))) {
    [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
  }
}

Set-DefaultEnv "COMPOSE_PROJECT_NAME" "vpw-local-workbench"
$ComposeProjectName = Get-ProcessEnv "COMPOSE_PROJECT_NAME"
Set-DefaultEnv "WORKBENCH_DB_VOLUME" "$ComposeProjectName-db-data"
Set-DefaultEnv "WORKBENCH_IMPORT_UPLOADS_VOLUME" "$ComposeProjectName-import-uploads"
Set-DefaultEnv "WORKBENCH_REPORTS_VOLUME" "$ComposeProjectName-reports"
Set-DefaultEnv "WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME" "$ComposeProjectName-provider-snapshots"
Set-DefaultEnv "WORKBENCH_PROVIDER_CACHE_VOLUME" "$ComposeProjectName-provider-cache"

function Show-Usage {
  Write-Host @"
Usage:
  powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 [start|stop|status|logs|smoke|reset|update|diagnostics]

Commands:
  start        Prepare .env when needed, build images, start db/backend/worker/frontend.
  stop         Stop the local Workbench containers, keeping data volumes.
  status       Show Docker Compose service status.
  logs         Follow recent service logs.
  smoke        Run the Docker quickstart API smoke test against the running backend.
  reset        Stop containers and delete this Workbench project's Docker volumes.
  update       Fast-forward git when clean, then rebuild and start the current checkout.
  diagnostics  Create a redacted diagnostics bundle under diagnostics\.

Environment overrides:
  `$env:DOCKER_DEMO_FRONTEND_PORT = "15174"
  `$env:DOCKER_DEMO_BACKEND_PORT = "18080"
  `$env:COMPOSE_PROJECT_NAME = "vpw-local-workbench"
  `$env:VPW_OPEN_BROWSER = "0"
  `$env:VPW_ASSUME_YES = "1"
"@
}

function Invoke-Compose {
  param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
  & docker compose @ComposeFiles @ComposeArgs
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE."
  }
}

function Test-CommandAvailable {
  param([Parameter(Mandatory = $true)][string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Assert-DockerReady {
  if (-not (Test-CommandAvailable "docker")) {
    throw "Docker is not installed. Install Docker Desktop, start it, then rerun this launcher."
  }
  & docker compose version *> $null
  if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose plugin is not available. Install or update Docker Desktop."
  }
  & docker info *> $null
  if ($LASTEXITCODE -ne 0) {
    throw "Docker is installed but not running. Start Docker Desktop, then rerun this launcher."
  }
}

function New-LocalSecret {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($bytes)
    return ([System.BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()
  }
  finally {
    $rng.Dispose()
  }
}

function Initialize-EnvFile {
  if (Test-Path ".env") {
    return
  }
  if (-not (Test-Path ".env.example")) {
    throw ".env is missing and .env.example was not found."
  }

  $secretKey = New-LocalSecret
  $postgresPassword = New-LocalSecret
  $lines = Get-Content ".env.example" | ForEach-Object {
    switch -Regex ($_) {
      "^SECRET_KEY=" { "SECRET_KEY=$secretKey"; break }
      "^POSTGRES_PASSWORD=" { "POSTGRES_PASSWORD=$postgresPassword"; break }
      "^DEMO_PROVIDER_SNAPSHOT_ENABLED=" { "DEMO_PROVIDER_SNAPSHOT_ENABLED=true"; break }
      "^DEMO_WORKSPACE_ENABLED=" { "DEMO_WORKSPACE_ENABLED=true"; break }
      default { $_ }
    }
  }
  Set-Content -Path ".env" -Value $lines -Encoding UTF8
  Write-Host "Created local .env from .env.example."
}

function Test-PortBusy {
  param([Parameter(Mandatory = $true)][int]$Port)
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
    $connected = $async.AsyncWaitHandle.WaitOne(300, $false)
    if ($connected -and $client.Connected) {
      $client.EndConnect($async)
      return $true
    }
    return $false
  }
  catch {
    return $false
  }
  finally {
    $client.Close()
  }
}

function Select-FreePort {
  param(
    [Parameter(Mandatory = $true)][string]$EnvName,
    [Parameter(Mandatory = $true)][int]$Preferred,
    [Parameter(Mandatory = $true)][int]$FallbackStart
  )

  $requested = Get-ProcessEnv $EnvName
  if (-not [string]::IsNullOrWhiteSpace($requested)) {
    $requestedPort = [int]$requested
    if (Test-PortBusy $requestedPort) {
      throw "Configured $EnvName=$requestedPort is already in use."
    }
    return $requestedPort
  }

  foreach ($port in @($Preferred, $FallbackStart)) {
    if (-not (Test-PortBusy $port)) {
      return $port
    }
  }

  for ($port = $FallbackStart; $port -lt ($FallbackStart + 100); $port++) {
    if (-not (Test-PortBusy $port)) {
      return $port
    }
  }

  throw "No free local port found near $Preferred or $FallbackStart."
}

function Test-ServiceRunning {
  param([Parameter(Mandatory = $true)][string]$Service)
  $services = & docker compose @ComposeFiles ps --services --status running 2>$null
  if ($LASTEXITCODE -ne 0) {
    return $false
  }
  return $services -contains $Service
}

function Get-PublishedPort {
  param(
    [Parameter(Mandatory = $true)][string]$Service,
    [Parameter(Mandatory = $true)][int]$ContainerPort
  )
  $published = & docker compose @ComposeFiles port $Service $ContainerPort 2>$null | Select-Object -Last 1
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($published)) {
    return ""
  }
  if ($published -match ":(\d+)$") {
    return $Matches[1]
  }
  return ""
}

function Set-LaunchPorts {
  if ((Test-ServiceRunning "frontend") -and (Test-ServiceRunning "backend")) {
    $existingFrontendPort = Get-PublishedPort "frontend" 8080
    $existingBackendPort = Get-PublishedPort "backend" 8000
    if ($existingFrontendPort -and $existingBackendPort) {
      [Environment]::SetEnvironmentVariable("DOCKER_DEMO_FRONTEND_PORT", $existingFrontendPort, "Process")
      [Environment]::SetEnvironmentVariable("DOCKER_DEMO_BACKEND_PORT", $existingBackendPort, "Process")
      return
    }
  }

  $frontendPort = Select-FreePort "DOCKER_DEMO_FRONTEND_PORT" 5173 15174
  $backendPort = Select-FreePort "DOCKER_DEMO_BACKEND_PORT" 8000 18080
  [Environment]::SetEnvironmentVariable("DOCKER_DEMO_FRONTEND_PORT", [string]$frontendPort, "Process")
  [Environment]::SetEnvironmentVariable("DOCKER_DEMO_BACKEND_PORT", [string]$backendPort, "Process")
}

function Set-RuntimeEnv {
  $frontendPort = Get-ProcessEnv "DOCKER_DEMO_FRONTEND_PORT"
  [Environment]::SetEnvironmentVariable("FRONTEND_HOST", "http://localhost:$frontendPort", "Process")
  [Environment]::SetEnvironmentVariable(
    "BACKEND_CORS_ORIGINS",
    "http://localhost,http://localhost:$frontendPort,http://127.0.0.1:$frontendPort",
    "Process"
  )
  [Environment]::SetEnvironmentVariable("VITE_API_URL", "", "Process")
}

function Wait-ForUrl {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$Url,
    [string]$Expected = ""
  )

  for ($attempt = 1; $attempt -le 60; $attempt++) {
    try {
      $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
      $body = [string]$response.Content
      if ([string]::IsNullOrEmpty($Expected) -or $body.Trim() -eq $Expected) {
        return
      }
    }
    catch {
      Start-Sleep -Seconds 2
    }
  }

  Write-Error "$Label did not become ready at $Url."
  & docker compose @ComposeFiles ps
  & docker compose @ComposeFiles logs --no-color --tail=120 backend frontend worker db
  throw "$Label did not become ready."
}

function Open-Frontend {
  param([Parameter(Mandatory = $true)][string]$Url)
  if ((Get-ProcessEnv "VPW_OPEN_BROWSER") -eq "0") {
    return
  }
  Start-Process $Url
}

function Write-WorkbenchUrls {
  $frontendPort = Get-ProcessEnv "DOCKER_DEMO_FRONTEND_PORT"
  $backendPort = Get-ProcessEnv "DOCKER_DEMO_BACKEND_PORT"
  Write-Host ""
  Write-Host "Vuln Prioritizer Workbench is running."
  Write-Host "Frontend:       http://127.0.0.1:$frontendPort"
  Write-Host "Backend health: http://127.0.0.1:$backendPort/api/v1/utils/health-check/"
  Write-Host ""
  Write-Host "Stop it with:   powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 stop"
}

function Start-Workbench {
  Write-Warning "Docker Compose/PostgreSQL is a deprecated compatibility path for this release. New source installations should use: pipx install ./backend; vpw serve"
  Assert-DockerReady
  Initialize-EnvFile
  Set-LaunchPorts
  Set-RuntimeEnv

  $frontendPort = Get-ProcessEnv "DOCKER_DEMO_FRONTEND_PORT"
  $backendPort = Get-ProcessEnv "DOCKER_DEMO_BACKEND_PORT"

  Write-Host "Starting Vuln Prioritizer Workbench with Docker Compose..."
  Write-Host "Compose project: $(Get-ProcessEnv 'COMPOSE_PROJECT_NAME')"
  Write-Host "Frontend port:   $frontendPort"
  Write-Host "Backend port:    $backendPort"

  Invoke-Compose -ComposeArgs @("up", "-d", "--build", "backend", "frontend", "worker")

  Wait-ForUrl "Backend health" "http://127.0.0.1:$backendPort/api/v1/utils/health-check/" "true"
  Wait-ForUrl "Frontend" "http://127.0.0.1:$frontendPort/"
  Write-WorkbenchUrls
  Open-Frontend "http://127.0.0.1:$frontendPort"
}

function Stop-Workbench {
  Assert-DockerReady
  Invoke-Compose -ComposeArgs @("down", "--remove-orphans")
}

function Show-Status {
  Assert-DockerReady
  Invoke-Compose -ComposeArgs @("ps")
}

function Show-Logs {
  Assert-DockerReady
  Invoke-Compose -ComposeArgs @("logs", "-f", "--tail=200", "backend", "frontend", "worker", "db")
}

function Invoke-Smoke {
  Assert-DockerReady
  Set-LaunchPorts
  $backendPort = Get-ProcessEnv "DOCKER_DEMO_BACKEND_PORT"
  [Environment]::SetEnvironmentVariable("DOCKER_QUICKSTART_API_BASE_URL", "http://127.0.0.1:$backendPort/api/v1", "Process")

  $python = Get-Command python3 -ErrorAction SilentlyContinue
  $pythonArgs = @("scripts/docker_quickstart_api_smoke.py")
  if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
  }
  if (-not $python) {
    $python = Get-Command py -ErrorAction SilentlyContinue
    $pythonArgs = @("-3", "scripts/docker_quickstart_api_smoke.py")
  }
  if (-not $python) {
    throw "Python 3 was not found. Install Python 3 to run the optional smoke test."
  }

  & $python.Source @pythonArgs
  if ($LASTEXITCODE -ne 0) {
    throw "Smoke test failed with exit code $LASTEXITCODE."
  }
}

function Confirm-Reset {
  if ((Get-ProcessEnv "VPW_ASSUME_YES") -eq "1") {
    return
  }
  Write-Host "This will delete Docker volumes for Compose project '$(Get-ProcessEnv 'COMPOSE_PROJECT_NAME')'."
  Write-Host "Uploaded imports, generated reports, provider cache, and the local database will be removed."
  $confirmation = Read-Host "Type RESET to continue"
  if ($confirmation -ne "RESET") {
    Write-Host "Reset cancelled."
    exit 0
  }
}

function Reset-Workbench {
  Assert-DockerReady
  Confirm-Reset
  Invoke-Compose -ComposeArgs @("down", "-v", "--remove-orphans")
  Write-Host "Deleted containers and volumes for Compose project '$(Get-ProcessEnv 'COMPOSE_PROJECT_NAME')'."
}

function Update-Workbench {
  if (Test-CommandAvailable "git") {
    & git rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -eq 0) {
      $status = & git status --short
      if ($status) {
        Write-Host "Working tree has local changes; skipping git pull."
        $status | ForEach-Object { Write-Host $_ }
      }
      else {
        & git rev-parse --abbrev-ref --symbolic-full-name "@{u}" *> $null
        if ($LASTEXITCODE -eq 0) {
          & git pull --ff-only
          if ($LASTEXITCODE -ne 0) {
            throw "git pull --ff-only failed with exit code $LASTEXITCODE."
          }
        }
        else {
          Write-Host "No upstream branch configured; skipping git pull."
        }
      }
    }
    else {
      Write-Host "Not a git checkout; skipping git pull."
    }
  }
  else {
    Write-Host "Git is not installed; skipping git pull."
  }
  Start-Workbench
}

function Redact-File {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path $Path)) {
    return
  }
  $content = Get-Content -Raw -Path $Path -ErrorAction SilentlyContinue
  if ($null -eq $content) {
    return
  }
  $content = $content -replace "(?i)((secret|password|token|api[_-]?key)[A-Za-z0-9_ .:-]*[=:]\s*)[^\s`",]+", '$1[REDACTED]'
  $content = $content -replace "(Bearer )[A-Za-z0-9._~+/=-]+", '$1[REDACTED]'
  Set-Content -Path $Path -Value $content -Encoding UTF8
}

function Write-CommandOutput {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$CommandName,
    [string[]]$Arguments = @()
  )
  $header = "`$ $CommandName $($Arguments -join ' ')`n"
  try {
    $output = & $CommandName @Arguments 2>&1 | Out-String
    Set-Content -Path $Path -Value ($header + $output) -Encoding UTF8
  }
  catch {
    Set-Content -Path $Path -Value ($header + $_.Exception.Message) -Encoding UTF8
  }
  Redact-File $Path
}

function Write-UrlOutput {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Url
  )
  try {
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
    Set-Content -Path $Path -Value ("GET $Url`n`n" + [string]$response.Content) -Encoding UTF8
  }
  catch {
    Set-Content -Path $Path -Value ("GET $Url`n`n" + $_.Exception.Message) -Encoding UTF8
  }
  Redact-File $Path
}

function Invoke-Diagnostics {
  Assert-DockerReady
  $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  $diagnosticsRoot = Join-Path $RootDir "diagnostics"
  $diagnosticsDir = Join-Path $diagnosticsRoot "workbench-diagnostics-$timestamp"
  New-Item -ItemType Directory -Force -Path $diagnosticsDir | Out-Null

  $frontendPort = Get-ProcessEnv "DOCKER_DEMO_FRONTEND_PORT"
  if ([string]::IsNullOrWhiteSpace($frontendPort)) {
    $frontendPort = Get-PublishedPort "frontend" 8080
  }
  $backendPort = Get-ProcessEnv "DOCKER_DEMO_BACKEND_PORT"
  if ([string]::IsNullOrWhiteSpace($backendPort)) {
    $backendPort = Get-PublishedPort "backend" 8000
  }

  @(
    "created_at_utc=$timestamp",
    "compose_project_name=$(Get-ProcessEnv 'COMPOSE_PROJECT_NAME')",
    "frontend_port=$frontendPort",
    "backend_port=$backendPort",
    "db_volume=$(Get-ProcessEnv 'WORKBENCH_DB_VOLUME')",
    "import_uploads_volume=$(Get-ProcessEnv 'WORKBENCH_IMPORT_UPLOADS_VOLUME')",
    "reports_volume=$(Get-ProcessEnv 'WORKBENCH_REPORTS_VOLUME')",
    "provider_snapshots_volume=$(Get-ProcessEnv 'WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME')",
    "provider_cache_volume=$(Get-ProcessEnv 'WORKBENCH_PROVIDER_CACHE_VOLUME')"
  ) | Set-Content -Path (Join-Path $diagnosticsDir "launcher-environment.txt") -Encoding UTF8

  Write-CommandOutput (Join-Path $diagnosticsDir "docker-version.txt") "docker" @("version")
  Write-CommandOutput (Join-Path $diagnosticsDir "docker-compose-version.txt") "docker" @("compose", "version")
  Write-CommandOutput (Join-Path $diagnosticsDir "compose-ps.txt") "docker" (@("compose") + $ComposeFiles + @("ps"))
  Write-CommandOutput (Join-Path $diagnosticsDir "compose-logs.txt") "docker" (@("compose") + $ComposeFiles + @("logs", "--no-color", "--tail=250", "backend", "frontend", "worker", "db"))

  if (Test-CommandAvailable "git") {
    & git rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -eq 0) {
      Write-CommandOutput (Join-Path $diagnosticsDir "git-status.txt") "git" @("status", "--short", "--branch")
      Write-CommandOutput (Join-Path $diagnosticsDir "git-commit.txt") "git" @("rev-parse", "HEAD")
    }
    else {
      Set-Content -Path (Join-Path $diagnosticsDir "git-status.txt") -Value "Not a git checkout." -Encoding UTF8
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($backendPort)) {
    Write-UrlOutput (Join-Path $diagnosticsDir "backend-workbench-status.json") "http://127.0.0.1:$backendPort/api/v1/workbench/status"
    Write-UrlOutput (Join-Path $diagnosticsDir "backend-provider-status.json") "http://127.0.0.1:$backendPort/api/v1/providers/status"
    Write-UrlOutput (Join-Path $diagnosticsDir "backend-demo-status.json") "http://127.0.0.1:$backendPort/api/v1/workbench/demo"
    Write-UrlOutput (Join-Path $diagnosticsDir "backend-health.txt") "http://127.0.0.1:$backendPort/api/v1/utils/health-check/"
  }
  else {
    Set-Content -Path (Join-Path $diagnosticsDir "backend-status-skipped.txt") -Value "Backend port is not available because the backend service is not running." -Encoding UTF8
  }

  @"
This diagnostics bundle intentionally excludes .env files, database dumps,
uploaded import files, generated reports, and provider cache contents.
Review files before sharing them outside your machine.
"@ | Set-Content -Path (Join-Path $diagnosticsDir "README.txt") -Encoding UTF8

  $archivePath = "$diagnosticsDir.zip"
  if (Test-Path $archivePath) {
    Remove-Item $archivePath
  }
  Compress-Archive -Path $diagnosticsDir -DestinationPath $archivePath
  Write-Host "Created diagnostics bundle: $archivePath"
}

switch ($Command) {
  "start" { Start-Workbench }
  "stop" { Stop-Workbench }
  "status" { Show-Status }
  "logs" { Show-Logs }
  "smoke" { Invoke-Smoke }
  "reset" { Reset-Workbench }
  "update" { Update-Workbench }
  "diagnostics" { Invoke-Diagnostics }
  "help" { Show-Usage }
}
