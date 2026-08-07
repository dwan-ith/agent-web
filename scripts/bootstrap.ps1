$ErrorActionPreference = "Stop"

$AgentWebRoot = Split-Path -Parent $PSScriptRoot
$AgentWebPython = Join-Path $AgentWebRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $AgentWebPython)) {
    python -m venv (Join-Path $AgentWebRoot ".venv")
}

& $AgentWebPython -m pip install --upgrade pip
& $AgentWebPython -m pip install `
    -e (Join-Path $AgentWebRoot "libagentweb\python") `
    -e (Join-Path $AgentWebRoot "agent-web-server\python") `
    -e (Join-Path $AgentWebRoot "sites\moltbook\python") `
    -e (Join-Path $AgentWebRoot "sites\forecast\python") `
    -e (Join-Path $AgentWebRoot "sites\registry\python") `
    -e (Join-Path $AgentWebRoot "line-mode-agent-browser\python") `
    -e (Join-Path $AgentWebRoot "agent-web-browser\python")

Push-Location (Join-Path $AgentWebRoot "libagentweb")
try {
    npm.cmd install
} finally {
    Pop-Location
}

$VendorDirectory = Join-Path $AgentWebRoot "agent-web-browser\vendor"
New-Item -ItemType Directory -Force -Path $VendorDirectory | Out-Null
Get-ChildItem -LiteralPath $VendorDirectory -Filter "agent-web-core-*.tgz" |
    Remove-Item -Force

Push-Location (Join-Path $AgentWebRoot "libagentweb")
try {
    npm.cmd pack --pack-destination $VendorDirectory
} finally {
    Pop-Location
}

Push-Location (Join-Path $AgentWebRoot "agent-web-browser")
try {
    npm.cmd install
    npm.cmd audit --audit-level=high
} finally {
    Pop-Location
}

Write-Host "Agent Web is ready. Run: .\.venv\Scripts\python.exe .\scripts\verify.py"
