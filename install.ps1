# AI Security Scanner - One-Click Installer (Windows PowerShell)
# Supports: Claude Code, OpenClaw, CLI
#
# Usage:
#   git clone https://github.com/javamagong/ai-security-scanner.git
#   cd ai-security-scanner
#   powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

$InstallDir = "$env:USERPROFILE\.ai-security-scanner"
$ClaudeCommandsDir = "$env:USERPROFILE\.claude\commands"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "🔒 AI Security Scanner - Installer" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# ── Check Python ──────────────────────────────────────────
$PythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 8) {
                $PythonCmd = $cmd
                Write-Host "✅ $ver" -ForegroundColor Green
                break
            }
        }
    } catch {}
}

if (-not $PythonCmd) {
    Write-Host "❌ Python 3.8+ is required." -ForegroundColor Red
    Write-Host "   Install: https://python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# ── Install Python dependencies ───────────────────────────
Write-Host "📦 Installing dependencies..."
& $PythonCmd -m pip install --quiet pyyaml colorama watchdog
Write-Host "✅ Dependencies installed" -ForegroundColor Green

# ── Copy to install dir ───────────────────────────────────
if ($ScriptDir -ne $InstallDir) {
    Write-Host "📂 Installing to $InstallDir..."
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    Copy-Item -Path "$ScriptDir\*" -Destination $InstallDir -Recurse -Force
}

# ── Claude Code: install slash command ────────────────────
$ClaudeDir = "$env:USERPROFILE\.claude"
if (Test-Path $ClaudeDir) {
    if (-not (Test-Path $ClaudeCommandsDir)) {
        New-Item -ItemType Directory -Path $ClaudeCommandsDir -Force | Out-Null
    }
    Copy-Item -Path "$InstallDir\.claude\commands\security-scan.md" -Destination $ClaudeCommandsDir -Force
    Write-Host "✅ Claude Code command installed → /security-scan" -ForegroundColor Green
} else {
    Write-Host "ℹ️  Claude Code not detected — skipping /security-scan command" -ForegroundColor Yellow
    Write-Host "   To install later: Copy-Item $InstallDir\.claude\commands\security-scan.md ~\.claude\commands\" -ForegroundColor Gray
}

# ── OpenClaw ──────────────────────────────────────────────
if (Get-Command openclaw -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "🦞 OpenClaw detected. Run to activate skill:" -ForegroundColor Cyan
    Write-Host "   openclaw skills install $InstallDir" -ForegroundColor White
} else {
    Write-Host "ℹ️  OpenClaw not detected — CLI mode only" -ForegroundColor Yellow
}

# ── Done ──────────────────────────────────────────────────
Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "Usage:" -ForegroundColor White
Write-Host ""
if (Test-Path $ClaudeDir) {
    Write-Host "  Claude Code (restart required):" -ForegroundColor Cyan
    Write-Host "    /security-scan"
    Write-Host "    /security-scan C:\path\to\project"
    Write-Host ""
}
Write-Host "  CLI:" -ForegroundColor Cyan
Write-Host "    $PythonCmd $InstallDir\auto_scanner.py"
Write-Host "    $PythonCmd $InstallDir\auto_scanner.py -d C:\path\to\project"
Write-Host "    $PythonCmd $InstallDir\auto_scanner.py -d . --ci"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
