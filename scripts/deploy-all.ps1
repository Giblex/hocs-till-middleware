# Pushes both the middleware (Railway) and the Shopify theme in one command.
#
# Usage (from the middleware folder):
#   pwsh ./scripts/deploy-all.ps1
#
# Optional flags:
#   -SkipMiddleware    Don't push middleware to git/Railway
#   -SkipTheme         Don't push theme to Shopify
#   -Live              Push theme to live theme (default: pushes to "Development" theme)
#
# Prerequisites (one-time):
#   - npm i -g @shopify/cli
#   - shopify auth login   (browser flow)
#   - railway login        (browser flow)

param(
  [switch]$SkipMiddleware,
  [switch]$SkipTheme,
  [switch]$Live
)

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$theme = 'C:\Users\Main\OneDrive\Documents\Work\HOCS\Website\Shoppify theme HTML'
$store = 'highonchapel.myshopify.com'

# ── Middleware → Railway via git push ─────────────────────────────────────────
if (-not $SkipMiddleware) {
  Write-Host "`n=== Middleware → Railway ===" -ForegroundColor Cyan
  Set-Location $root
  $status = git status --porcelain
  if ($status) {
    Write-Host "Uncommitted changes detected — staging and committing." -ForegroundColor Yellow
    git add -A
    git -c user.email=Giblex@users.noreply.github.com commit -m "deploy: auto-commit from deploy-all.ps1"
  }
  $ahead = git rev-list --count '@{u}..HEAD' 2>$null
  if ($ahead -and [int]$ahead -gt 0) {
    git push
    Write-Host "Pushed $ahead commit(s). Railway will auto-deploy." -ForegroundColor Green
  } else {
    Write-Host "Nothing new to push." -ForegroundColor Gray
  }
}

# ── Theme → Shopify via CLI push ──────────────────────────────────────────────
if (-not $SkipTheme) {
  Write-Host "`n=== Theme → Shopify ===" -ForegroundColor Cyan
  if (-not (Test-Path $theme)) {
    Write-Host "Theme folder not found: $theme" -ForegroundColor Red
    exit 1
  }
  Set-Location $theme

  $args = @('theme', 'push', "--store=$store", '--allow-live', '--ignore=build_projects_structure_*.txt', '--ignore=Ignore Presets/*')
  if ($Live) {
    Write-Host "Pushing to LIVE theme — Ctrl+C now if that's not what you want." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    $args += '--live'
  } else {
    $args += @('--unpublished', '--theme=hocs-dev')
  }
  & shopify @args
  if ($LASTEXITCODE -ne 0) { Write-Host "Theme push failed." -ForegroundColor Red; exit $LASTEXITCODE }
  Write-Host "Theme pushed." -ForegroundColor Green
}

Write-Host "`nAll done." -ForegroundColor Green
