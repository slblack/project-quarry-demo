<#
.SYNOPSIS
  Starts the Project Quarry demo in Docker on this computer (Windows).

.DESCRIPTION
  - Checks Docker is running.
  - If the certs folder is empty, exports your network's HTTPS-inspection CA (for example Cisco
    Secure Access) so the container can reach OpenAI / AI Defense. Skipped when traffic is not inspected.
  - Pulls the latest image, replaces any existing container, and mounts this folder's certs
    folder by full path (so it works from any current directory).
  - Waits until the app responds, then opens http://127.0.0.1:<port>.
  Saved API keys live in the "quarry-demo-data" Docker volume and survive restarts and upgrades.

.EXAMPLE
  .\start.ps1
.EXAMPLE
  .\start.ps1 -Port 5076 -NoPull
.EXAMPLE
  .\start.ps1 -Build      (build the image from this folder instead of pulling it)
#>
param(
  [string]$Image = "ghcr.io/slblack/project-quarry-demo:latest",
  [int]$Port = 5075,
  [switch]$NoPull,
  [switch]$Build,
  [switch]$NoCertExport,
  [switch]$RelaxStrictTls,
  [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Name = "project-quarry-demo"
$Volume = "quarry-demo-data"
$Root = $PSScriptRoot
$Certs = Join-Path $Root "certs"

function Step($text) { Write-Host ""; Write-Host "==> $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host ""; Write-Host $text -ForegroundColor Red; exit 1 }
function Invoke-Docker {
  # Runs docker and returns its combined output as text, without PowerShell treating stderr as an error.
  $argLine = ($args | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join " "
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "docker"
  $psi.Arguments = $argLine
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $errTask = $p.StandardError.ReadToEndAsync()   # read both streams at once so neither can fill up and block
  $out = $p.StandardOutput.ReadToEnd()
  $p.WaitForExit()
  $out = $out + $errTask.Result
  return [pscustomobject]@{ Code = $p.ExitCode; Output = $out.Trim() }
}
function Test-PortFree($p) {
  # Busy only if something is actually listening (recently closed connections do not count).
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $async = $c.BeginConnect([System.Net.IPAddress]::Loopback, $p, $null, $null)
    if ($async.AsyncWaitHandle.WaitOne(1000) -and $c.Connected) { return $false }
    return $true
  } catch { return $true } finally { $c.Close() }
}
function Test-AppReady($p) {
  try {
    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$p/healthz")
    $req.Proxy = $null            # never send local traffic through a corporate proxy
    $req.Timeout = 2000
    $resp = $req.GetResponse()
    $ok = ([int]$resp.StatusCode -eq 200)
    $resp.Close()
    return $ok
  } catch { return $false }
}

# 1. Docker available and running?
Step "Checking Docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Fail "Docker was not found. Install Docker Desktop (https://www.docker.com/products/docker-desktop/) and try again."
}
$info = Invoke-Docker info --format "{{.ServerVersion}}"
if ($info.Code -ne 0) { Fail "Docker is installed but not running. Start Docker Desktop, wait until it says 'Engine running', then try again." }
Write-Host "Docker engine $($info.Output) is running."

# 2. Network CA certificates
Step "Checking network certificates"
New-Item -ItemType Directory -Force -Path $Certs | Out-Null
$certFiles = @(Get-ChildItem -Path $Certs -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in ".pem", ".crt" })
if ($certFiles.Count -eq 0 -and -not $NoCertExport) {
  Write-Host "No certificates in $Certs yet - checking whether your network inspects HTTPS..."
  $exporter = Join-Path $Root "scripts\export-network-root-ca.ps1"
  try {
    & $exporter -SkipIfPublic
  } catch {
    Write-Host "Certificate export did not complete: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "The app will still start; if OpenAI verification reports a TLS error, see README section "Corporate networks"." -ForegroundColor Yellow
  }
  $certFiles = @(Get-ChildItem -Path $Certs -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in ".pem", ".crt" })
}
if ($certFiles.Count -gt 0) {
  Write-Host "Using certificate file(s): $($certFiles.Name -join ', ')"
} else {
  Write-Host "No extra certificates (not needed unless your network inspects HTTPS)."
}

# 3. Image
if ($Build) {
  $Image = "project-quarry-demo:local"
  Step "Building $Image from this folder (the first build takes a few minutes)"
  $b = Invoke-Docker build -t $Image $Root
  if ($b.Code -ne 0) { Write-Host $b.Output; Fail "The image could not be built. The build log is shown above." }
  Write-Host "Image built."
}
elseif (-not $NoPull -and $Image -match "/") {
  Step "Pulling $Image"
  $pull = Invoke-Docker pull $Image
  if ($pull.Code -ne 0) {
    $have = Invoke-Docker image inspect $Image --format "{{.Id}}"
    if ($have.Code -ne 0) {
      Write-Host $pull.Output
      Fail "Could not pull $Image and no local copy exists. If you have not published the image yet, build it here instead: .\start.ps1 -Build"
    }
    Write-Host "Could not pull the latest image; using the copy already on this computer." -ForegroundColor Yellow
  } else {
    Write-Host "Image is up to date."
  }
}

# 4. Replace any existing container
Step "Starting the container"
$existing = Invoke-Docker ps -a --filter "name=^/$Name$" --format "{{.ID}}"
if ($existing.Output) {
  Write-Host "Removing the previous $Name container (saved settings are kept in the '$Volume' volume)."
  [void](Invoke-Docker rm -f $Name)
  Start-Sleep -Seconds 1
}
if (-not (Test-PortFree $Port)) {
  Fail "Port $Port on 127.0.0.1 is already in use by another program. Run again with a different port, for example: .\start.ps1 -Port 5076"
}

$runArgs = @("run", "-d", "--name", $Name,
  "-p", "127.0.0.1:${Port}:5075",
  "-v", "${Volume}:/data",
  "-v", "${Certs}:/certs:ro")
if ($RelaxStrictTls) { $runArgs += @("-e", "QUARRY_DEMO_TLS_RELAX_X509_STRICT=1") }
$runArgs += $Image
$run = Invoke-Docker @runArgs
if ($run.Code -ne 0) { Write-Host $run.Output; Fail "The container could not be started." }

# 5. Wait for the app
Write-Host "Waiting for the app to start..."
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
  if (Test-AppReady $Port) { $ready = $true; break }
  $state = Invoke-Docker inspect -f "{{.State.Running}}" $Name
  if ($state.Output -ne "true") { break }
  Start-Sleep -Milliseconds 750
}
$logs = (Invoke-Docker logs $Name).Output
if (-not $ready) {
  Write-Host $logs
  Fail "The app did not start. The container log is shown above."
}
$caLine = ($logs -split "`n") | Where-Object { $_ -match "extra CA certificate|Skipped .*certificate" }
foreach ($line in $caLine) { Write-Host ($line -replace "^\S+ \S+ \S+ \S+: ", "") }

$url = "http://127.0.0.1:$Port"
Step "The Project Quarry demo is running at $url"
Write-Host "Scripted scenarios work straight away. Open Setup to add an OpenAI key for live mode."
Write-Host "Stop it with: .\stop.ps1   (or: docker stop $Name)"
if (-not $NoBrowser) { Start-Process $url }
