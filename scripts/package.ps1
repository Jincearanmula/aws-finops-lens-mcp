# Builds a shareable ZIP from git-tracked files only.
# Untracked/ignored files (.env, .venv, logs) are never included.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (git status --porcelain) {
    Write-Warning "Uncommitted changes are NOT included. Commit first if you need them."
}

$out = "aws-finops-mcp-$(git rev-parse --short HEAD).zip"
git archive --format=zip --output=$out HEAD

$bad = (& tar -tf $out) | Where-Object { $_ -match '(^|/)(\.env$|\.env\.(?!example)|\.venv/|venv/|.*\.log$|.*\.pem$)' }
if ($bad) {
    Remove-Item $out
    throw "Refusing to package - sensitive files found: $($bad -join ', ')"
}
Write-Host "Created $out"
