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
# Theme has its own git repo (Giblex/hocs-shopify-theme) connected to Shopify
# via the GitHub theme integration. We push to GitHub; Shopify auto-deploys.
$theme = 'C:\Users\Main\hocs-theme-new'
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

# ── Theme → GitHub → Shopify (auto-deploys via GitHub theme integration) ─────
if (-not $SkipTheme) {
  Write-Host "`n=== Theme → GitHub (Shopify auto-deploys) ===" -ForegroundColor Cyan
  if (-not (Test-Path $theme)) {
    Write-Host "Theme folder not found: $theme" -ForegroundColor Red
    exit 1
  }
  Set-Location $theme
  $status = git status --porcelain
  if ($status) {
    Write-Host "Uncommitted theme changes detected — staging and committing." -ForegroundColor Yellow
    git add -A
    git -c user.email=Giblex@users.noreply.github.com commit -m "deploy: auto-commit from deploy-all.ps1"
  }
  $ahead = git rev-list --count '@{u}..HEAD' 2>$null
  if ($ahead -and [int]$ahead -gt 0) {
    git push
    Write-Host "Pushed $ahead theme commit(s). Shopify will pull within ~30s." -ForegroundColor Green
  } else {
    Write-Host "Nothing new to push for theme." -ForegroundColor Gray
  }
}

Write-Host "`nAll done." -ForegroundColor Green
