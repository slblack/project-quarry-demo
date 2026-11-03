<#
.SYNOPSIS
  Stops and removes the the Project Quarry demo container (Windows).
  Saved settings and API keys stay in the "quarry-demo-data" Docker volume.
  Use -DeleteSavedSettings to also delete that volume (removes saved keys).
#>
param([switch]$DeleteSavedSettings)

$Name = "project-quarry-demo"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Host "Docker was not found."; exit 1 }
$id = (& docker ps -a --filter "name=^/$Name$" --format "{{.ID}}") 2>$null
if ($id) {
  & docker rm -f $Name *> $null
  Write-Host "Stopped and removed the $Name container."
} else {
  Write-Host "No $Name container is running."
}
if ($DeleteSavedSettings) {
  & docker volume rm quarry-demo-data *> $null
  Write-Host "Deleted the saved settings volume (quarry-demo-data), including saved API keys."
} else {
  Write-Host "Saved settings and API keys are kept for next time."
}
