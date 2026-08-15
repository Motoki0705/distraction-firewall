[CmdletBinding()]
param(
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repositoryRoot 'DistractionFirewall.slnx'
$arguments = @(
    'format'
    $solution
    '--no-restore'
    '--verbosity'
    'minimal'
)

if (-not $Fix) {
    $arguments += '--verify-no-changes'
}

Push-Location -LiteralPath $repositoryRoot
try {
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet format failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
