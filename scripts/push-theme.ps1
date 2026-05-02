# Push the Shopify theme to the store. Wraps the Shopify CLI with the
# right store/path defaults so it's a single command.
#
# First-time setup (run once, ever, on this machine):
#   npm i -g @shopify/cli @shopify/theme
#   shopify auth login
#
# Usage (from anywhere):
#   pwsh C:\Users\Main\hocs-till-middleware\scripts\push-theme.ps1
#   pwsh ... -Live          # publish to the live theme (with confirmation)
#   pwsh ... -DryRun        # show what would change without pushing

param(
  [switch]$Live,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$theme = 'C:\Users\Main\OneDrive\Documents\Work\HOCS\Website\Shoppify theme HTML'
$store = 'highonchapel.myshopify.com'

if (-not (Test-Path $theme)) {
  Write-Host "Theme folder not found: $theme" -ForegroundColor Red
  exit 1
}
Set-Location $theme

$cmdArgs = @('theme', 'push', "--store=$store", '--ignore=build_projects_structure_*.txt', '--ignore=Ignore Presets/*')

if ($DryRun) {
  $cmdArgs += '--dry-run'
}

if ($Live) {
  Write-Host "Pushing to LIVE theme on $store. Ctrl+C in 3s if not intended." -ForegroundColor Yellow
  Start-Sleep -Seconds 3
  $cmdArgs += @('--live', '--allow-live')
} else {
  $cmdArgs += @('--unpublished', '--theme=hocs-dev')
}

Write-Host "Running: shopify $($cmdArgs -join ' ')" -ForegroundColor Cyan
& shopify @cmdArgs
exit $LASTEXITCODE
